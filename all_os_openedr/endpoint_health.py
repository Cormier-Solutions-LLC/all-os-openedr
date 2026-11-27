"""Check enrolled execution protection, kernel sensors, and Wazuh connectivity."""

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
from pathlib import Path

from .ima_probe import IMA_RESULTS, prepare_probes
from .launch_broker import HEALTH_RESULTS, PEER, SOCKET_PATH, receive_message, send_message


WAZUH_STATE = "/var/ossec/var/run/wazuh-agentd.state"
HEALTH_LOG = "/var/log/all-os-openedr-health/checks.jsonl"
STATE_MAX_AGE = 30
STATE_MAX_BYTES = 16 * 1024
WAZUH_STATUSES = {b"'connected'": "connected", b"'disconnected'": "disconnected", b"'pending'": "pending"}
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
SENSORS = {
    "lifecycle": "all-os-openedr-lifecycle.service",
    "file_provenance": "all-os-openedr-file-provenance.service",
    "executable": "all-os-openedr-executable.service",
    "containment_audit": "all-os-openedr-containment-audit.service",
    "removable_storage": "all-os-openedr-removable-storage.service",
    "removable_copies": "all-os-openedr-removable-copies.service",
    "tcp": "all-os-openedr-tcp.service",
    "dns": "all-os-openedr-dns.service",
    "protocol": "all-os-openedr-protocol.service",
}
HEALTHY_SENSOR_STATES = {"active", "disabled", "masked", "not_installed"}


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


def sensor_status(properties):
    load, unit, active, sub = (properties.get(name) for name in ("LoadState", "UnitFileState", "ActiveState", "SubState"))
    if load == "not-found":
        return "not_installed"
    if unit in {"masked", "masked-runtime"} and active != "active":
        return "masked"
    if load != "loaded" or not active:
        return "unavailable"
    if active == "active" and sub == "running":
        return "active"
    if unit == "disabled" and active == "inactive":
        return "disabled"
    if sub == "auto-restart":
        return "restarting"
    if active in {"failed", "activating", "deactivating", "inactive"}:
        return active
    return "unavailable"


def sensor_health():
    command = [
        "/usr/bin/systemctl", "show", "--no-pager",
        "--property=Id,LoadState,UnitFileState,ActiveState,SubState", *SENSORS.values(),
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        result = None
    records = {}
    if result is not None:
        for block in result.stdout.strip().split("\n\n"):
            properties = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            if name := properties.get("Id"):
                records[name] = properties
    return {name: sensor_status(records.get(unit, {})) for name, unit in SENSORS.items()}


def sample():
    broker, ima = broker_health()
    forwarder = forwarder_health()
    sensors = sensor_health()
    sensors_ready = all(state in HEALTHY_SENSOR_STATES for state in sensors.values())
    ready = broker == "ready" and ima == "enforcing" and forwarder == "connected" and sensors_ready
    report = {
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
        "openedr_health_sensors": "ready" if sensors_ready else "degraded",
        **{f"openedr_health_sensor_{name}": state for name, state in sensors.items()},
    }
    try:
        report["openedr_boot_id"] = BOOT_ID.read_text(encoding="ascii").strip()
    except OSError:
        pass
    return report


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
