"""Check enrolled execution protection and local Wazuh connectivity."""

import argparse
import json
import os
import pwd
import socket
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone

from .ima_probe import IMA_RESULTS, prepare_probes
from .launch_broker import HEALTH_RESULTS, PEER, SOCKET_PATH, receive_message, send_message


WAZUH_STATE = "/var/ossec/var/run/wazuh-agentd.state"
HEALTH_LOG = "/var/log/all-os-openedr-health/checks.jsonl"
STATE_MAX_AGE = 30
STATE_MAX_BYTES = 16 * 1024
WAZUH_STATUSES = {b"'connected'": "connected", b"'disconnected'": "disconnected", b"'pending'": "pending"}


def broker_health():
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(SOCKET_PATH)
            _, uid, _ = PEER.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, PEER.size))
            if uid != 0:
                return "broker_peer_untrusted", "unknown"
            send_message(connection, {"health": True})
            report = receive_message(connection, 25)
    except OSError:
        return "broker_unavailable", "unknown"
    except (ValueError, RecursionError):
        return "broker_protocol_error", "unknown"
    if isinstance(report, dict) and report.keys() == {"broker", "ima"}:
        broker, ima = report["broker"], report["ima"]
        if isinstance(broker, str) and broker in HEALTH_RESULTS and isinstance(ima, str) and ima in IMA_RESULTS:
            return broker, ima
    return "broker_protocol_error", "unknown"


def forwarder_health():
    try:
        owners = {0, pwd.getpwnam("wazuh").pw_uid}
        descriptor = os.open(WAZUH_STATE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as state:
            metadata = os.fstat(state.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid not in owners or metadata.st_mode & 0o022:
                return "state_invalid"
            data = state.read(STATE_MAX_BYTES + 1)
            if os.fstat(state.fileno()).st_mtime_ns != metadata.st_mtime_ns:
                return "state_changing"
    except (OSError, KeyError):
        return "state_unavailable"
    age = time.time() - metadata.st_mtime
    if not 0 <= age <= STATE_MAX_AGE:
        return "state_stale"
    statuses = [line.removeprefix(b"status=") for line in data.splitlines() if line.startswith(b"status=")]
    if len(data) > STATE_MAX_BYTES or len(statuses) != 1:
        return "state_invalid"
    return WAZUH_STATUSES.get(statuses[0], "state_invalid")


def sample():
    broker, ima = broker_health()
    forwarder = forwarder_health()
    ready = broker == "ready" and ima == "enforcing" and forwarder == "connected"
    return {
        "openedr_source": "all-os-openedr",
        "openedr_schema": 1,
        "openedr_event": "endpoint.protection_health",
        "openedr_event_id": str(uuid.uuid4()),
        "openedr_host": socket.gethostname(),
        "openedr_observed_at": datetime.now(timezone.utc).isoformat(),
        "openedr_health_status": "ready" if ready else "degraded",
        "openedr_health_broker": broker,
        "openedr_health_ima": ima,
        "openedr_health_forwarder": forwarder,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--prepare-ima", metavar="MOUNT", help="Install the fixed IMA canaries on this execution volume")
    action.add_argument("--record", action="store_true", help="Append the sample to the systemd-managed health log")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Endpoint health requires root")
    if args.prepare_ima is not None:
        try:
            prepare_probes(args.prepare_ima)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            parser.error(str(error))
        return 0
    report = sample()
    line = json.dumps(report, separators=(",", ":"))
    if args.record:
        try:
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            with os.fdopen(os.open(HEALTH_LOG, flags, 0o640), "a", encoding="ascii") as log:
                metadata = os.fstat(log.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ValueError("The health log requires a root-owned regular file with root-only write access")
                log.write(line + "\n")
        except (OSError, ValueError) as error:
            parser.error(str(error))
    else:
        print(line)
    return int(report["openedr_health_status"] != "ready")
