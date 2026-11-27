"""Allow a local user to request an administrator-enrolled sandbox launch."""

import argparse
import json
import os
import re
import socket
import stat
import struct
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

from .apparmor_policy import trusted_file
from .containment import LAUNCH_FAILED, emit, launch, launch_event


SOCKET_PATH = "/run/all-os-openedr-launch.sock"
POLICY_PATH = Path("/etc/all-os-openedr-launch.json")
APPLICATION = re.compile(r"[a-z][a-z0-9-]{0,63}")
MAX_MESSAGE = 4096
MAX_POLICY = 65536
LAUNCH_TIMEOUT = 30
PEER = struct.Struct("=iII")


def receive_message(connection, timeout):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while len(data) <= MAX_MESSAGE:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Launch message expired")
        connection.settimeout(remaining)
        chunk = connection.recv(MAX_MESSAGE + 1 - len(data))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            if len(data) > MAX_MESSAGE or data.count(b"\n") != 1 or data[-1] != 10:
                break
            return json.loads(data.decode("utf-8"))
    raise ValueError("Invalid launch message")


def send_message(connection, message):
    connection.settimeout(3)
    connection.sendall(json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n")


def parse_policy(value):
    if (not isinstance(value, dict) or set(value) != {"schema", "filesystem", "uuid", "catalog", "applications"}
            or type(value["schema"]) is not int or value["schema"] != 1):
        raise ValueError("Invalid launch policy schema")
    filesystem, catalog = value["filesystem"], value["catalog"]
    if any(not isinstance(path, str) or not Path(path).is_absolute() or "\0" in path
           for path in (filesystem, catalog)):
        raise ValueError("Launch policy paths must be absolute")
    if not isinstance(value["uuid"], str):
        raise ValueError("Invalid execution volume UUID")
    volume = uuid.UUID(value["uuid"])
    if not volume.int:
        raise ValueError("Invalid execution volume UUID")
    applications = value["applications"]
    if not isinstance(applications, dict):
        raise ValueError("Invalid launch policy applications")
    for name, app in applications.items():
        if not APPLICATION.fullmatch(name) or not isinstance(app, dict) or set(app) != {"program", "uids", "arguments"}:
            raise ValueError("Invalid application policy")
        program, uids, arguments = app["program"], app["uids"], app["arguments"]
        if (not isinstance(program, str) or "\0" in program or not Path(program).parts
                or Path(program).is_absolute() or ".." in Path(program).parts):
            raise ValueError("Application paths must be relative to the execution volume")
        if not isinstance(uids, list) or any(type(uid) is not int or not 0 < uid < 0xFFFFFFFF for uid in uids):
            raise ValueError("Invalid application caller UIDs")
        if (not isinstance(arguments, list) or len(arguments) > 16
                or any(not isinstance(arg, str) or "\0" in arg or len(arg.encode("utf-8")) > 256 for arg in arguments)):
            raise ValueError("Invalid application arguments")
    return filesystem, str(volume), catalog, applications


def read_policy():
    trusted_file(POLICY_PATH)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(POLICY_PATH, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Invalid launch policy ownership")
        data = stream.read(MAX_POLICY + 1)
    if len(data) > MAX_POLICY:
        raise ValueError("Launch policy is too large")
    return parse_policy(json.loads(data))


def service(connection):
    _, uid, _ = PEER.unpack(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, PEER.size))
    event = launch_event()
    event["openedr_requester_uid"] = uid
    reply = {"event_id": event["openedr_event_id"]}

    def report(record, decision, reason, **details):
        emit(record, decision, reason, **details)
        reply.update(decision=decision, reason=reason)

    def block(reason):
        report(event, "blocked", reason)
        send_message(connection, {**reply, "exit_code": LAUNCH_FAILED})

    try:
        request = receive_message(connection, 3)
    except (OSError, ValueError, RecursionError):
        block("invalid_request")
        return
    if (not isinstance(request, dict) or set(request) != {"application"}
            or not isinstance(request["application"], str) or not APPLICATION.fullmatch(request["application"])):
        block("invalid_request")
        return
    try:
        filesystem, volume, catalog, applications = read_policy()
    except (OSError, ValueError, RuntimeError):
        block("launch_policy_unavailable")
        return
    name = request["application"]
    app = applications.get(name)
    if app is None or uid == os.getuid() or uid not in app["uids"]:
        block("request_not_authorized")
        return
    event["openedr_containment_application"] = name
    options = SimpleNamespace(
        catalog=catalog, execution_volume=(filesystem, volume), program=Path(filesystem) / app["program"],
        arguments=app["arguments"], timeout=LAUNCH_TIMEOUT,
    )
    try:
        code = launch(options, event, delegated=True, reporter=report)
    except (OSError, ValueError, RuntimeError):
        block("launch_failed")
        return
    send_message(connection, {**reply, "exit_code": code})


def service_main():
    if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        print("Launch service requires a dedicated unprivileged account", file=sys.stderr)
        return 1
    try:
        with socket.socket(fileno=0) as connection:
            if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM:
                return 1
            service(connection)
    except OSError:
        return 1
    return 0


def client_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("application", help="application name from the administrator's launch policy")
    options = parser.parse_args()
    if not APPLICATION.fullmatch(options.application):
        parser.error("Use a lowercase application name with letters, digits, and hyphens")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(SOCKET_PATH)
            send_message(connection, {"application": options.application})
            reply = receive_message(connection, LAUNCH_TIMEOUT + 10)
        if (not isinstance(reply, dict) or set(reply) != {"decision", "reason", "event_id", "exit_code"}
                or reply["decision"] not in ("blocked", "isolated")
                or not isinstance(reply["reason"], str) or not re.fullmatch(r"[a-z_]{1,64}", reply["reason"])
                or not isinstance(reply["event_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", reply["event_id"])
                or type(reply["exit_code"]) is not int or not 0 <= reply["exit_code"] <= 255):
            raise ValueError("Invalid launch result")
    except (OSError, ValueError, RecursionError):
        print("Launch service unavailable or request refused", file=sys.stderr)
        return LAUNCH_FAILED
    print(f"{reply['decision']} {reply['reason']} {reply['event_id']}",
          file=sys.stderr if reply["decision"] == "blocked" else sys.stdout)
    return reply["exit_code"]
