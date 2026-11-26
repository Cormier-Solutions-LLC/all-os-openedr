"""Forward individual kernel IMA appraisal failures from the Audit dispatcher."""

import hashlib
import json
import os
import re
import signal
import socket
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from .file_provenance import visible_text


LOG = Path("/var/log/all-os-openedr-ima/audit.jsonl")
APPRAISAL = re.compile(
    rb'(?:node=\S+ )?type=INTEGRITY_DATA msg=audit\((\d{1,12}\.\d{1,9}):(\d{1,20})\): '
    rb'pid=(\d{1,10}) uid=(\d{1,10}) auid=(\d{1,10}) ses=\d+ '
    rb'(?:subj=\S+ )?op=appraise_data cause=([a-zA-Z0-9_-]+) '
)
FAILURE = re.compile(rb' res=0 errno=-?\d+$')
FILENAME = re.compile(rb' name=(?:"([^"]*)"|([0-9A-Fa-f]+))(?= dev=| ino=| res=)')


def parse_failure(line, host, boot_id):
    if len(line) > 16 * 1024:
        return None
    line = line.rstrip(b"\r\n\0")
    core = line.split(b"\x1d", 1)[0]
    matched = APPRAISAL.match(core)
    if matched is None or FAILURE.search(core, matched.end()) is None:
        return None
    stamp, serial, pid, uid, auid, cause = matched.groups()
    try:
        observed = datetime.fromtimestamp(float(stamp), timezone.utc)
    except (OverflowError, ValueError, OSError):
        return None
    event = {
        "openedr_source": "all-os-openedr",
        "openedr_schema": 1,
        "openedr_event": "executable.integrity_failure",
        "openedr_event_id": hashlib.sha256(boot_id.encode() + b":ima:" + core).hexdigest(),
        "openedr_host": host,
        "openedr_boot_id": boot_id,
        "openedr_observed_at": observed.isoformat(timespec="milliseconds"),
        "openedr_pid": int(pid),
        "openedr_ima_uid": int(uid),
        "openedr_ima_auid": int(auid),
        "openedr_ima_audit_serial": serial.decode("ascii"),
        "openedr_ima_cause": cause.decode("ascii"),
        "openedr_ima_record": visible_text(line),
    }
    filename = FILENAME.search(core, matched.end())
    if filename:
        quoted, encoded = filename.groups()
        if quoted is not None:
            event["openedr_executable_path"] = visible_text(quoted)
        elif len(encoded) % 2 == 0:
            event["openedr_executable_path"] = visible_text(bytes.fromhex(encoded.decode("ascii")))
    return event


def append(event):
    fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as output:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise OSError("IMA dispatch requires a root-owned regular log file")
        output.write(json.dumps(event, separators=(",", ":")) + "\n")


def main():
    # Auditd may reload while the plugin reads events. Each write reopens the log for rotation.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    os.umask(0o077)
    metadata = LOG.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("IMA dispatch requires a root-owned log directory")
    host = socket.gethostname()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    for line in sys.stdin.buffer:
        event = parse_failure(line, host, boot_id)
        if event is not None:
            append(event)
