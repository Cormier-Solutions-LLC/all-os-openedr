"""Translate scoped kernel syscall exit events into containment evidence."""

import hashlib
import os
import platform
import pwd
import re
import socket
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .ima_audit import append


UNSET = 2**32 - 1
LOG = Path("/var/log/all-os-openedr-containment-audit/events.jsonl")
SCRIPT = "/usr/share/all-os-openedr/containment/decisions.bt"
RECORD = re.compile(
    rb"(\d{1,10}) (\d{1,10}) (\d{1,19}) "
    rb"(2|41|85|257|437|limit) (-?\d{1,10})\n"
)
OPERATIONS = {b"2": "open", b"41": "socket", b"85": "creat", b"257": "openat", b"437": "openat2"}


def start_audit_session(uid, proc=Path("/proc/self")):
    login = proc / "loginuid"
    session = proc / "sessionid"
    try:
        if int(login.read_text()) != UNSET or int(session.read_text()) != UNSET:
            return None
        login.write_text(str(uid))
        value = int(session.read_text())
    except (OSError, ValueError):
        return None
    return value if 0 <= value < UNSET else None


def parse_event(line, host, boot_id, uid):
    match = RECORD.fullmatch(line)
    if match is None:
        return None
    session, pid, stamp, probe, outcome = match.groups()
    session, pid, stamp, outcome = map(int, (session, pid, stamp, outcome))
    if session >= UNSET or not 0 < pid < 2**31 or not 0 < stamp < 2**63 or not -4095 <= outcome < 2**31:
        return None
    record = {
        "openedr_source": "all-os-openedr",
        "openedr_schema": 1,
        "openedr_event": "executable.sandbox_activity",
        "openedr_event_id": hashlib.sha256(boot_id.encode() + b":sandbox-activity:" + line).hexdigest(),
        "openedr_host": host,
        "openedr_boot_id": boot_id,
        "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "openedr_pid": pid,
        "openedr_uid": uid,
        "openedr_kernel_monotonic_ns": stamp,
        "openedr_containment_audit_session": session,
    }
    if probe == b"limit":
        record["openedr_containment_activity_result"] = "limit_reached"
        return record
    operation = OPERATIONS[probe]
    record["openedr_containment_activity_operation"] = operation
    record["openedr_containment_activity_class"] = "network" if operation == "socket" else "file"
    record["openedr_containment_activity_result"] = "failed" if outcome < 0 else "succeeded"
    if outcome < 0:
        record["openedr_containment_activity_errno"] = -outcome
    return record


def main():
    if os.geteuid() != 0 or platform.machine() != "x86_64":
        raise ValueError("Containment activity collection requires root on Linux amd64")
    uid = pwd.getpwnam("openedr-broker").pw_uid
    if uid == 0:
        raise ValueError("Containment activity requires an unprivileged broker account")
    metadata = LOG.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("Containment activity requires a root-owned log directory")
    host = socket.gethostname()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    command = ["/usr/bin/bpftrace", "-q", "-B", "line", SCRIPT, str(uid)]
    with subprocess.Popen(command, stdout=subprocess.PIPE) as tracer:
        try:
            for line in tracer.stdout:
                record = parse_event(line, host, boot_id, uid)
                if record is not None:
                    append(record, log=LOG)
        finally:
            if tracer.poll() is None:
                tracer.terminate()
        return tracer.wait()
