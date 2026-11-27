"""Allow a local user to request an administrator-enrolled sandbox launch."""

import argparse
import array
import codecs
import fcntl
import json
import os
import re
import select
import socket
import stat
import struct
import sys
import threading
import time
import uuid
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from types import SimpleNamespace

from .apparmor_policy import trusted_file
from .containment import LAUNCH_FAILED, emit, launch, launch_event
from .sandbox_audit import start_audit_session


SOCKET_PATH = "/run/all-os-openedr-launch.sock"
POLICY_PATH = Path("/etc/all-os-openedr-launch.json")
APPLICATION = re.compile(r"[a-z][a-z0-9-]{0,63}")
MAX_MESSAGE = 4096
MAX_POLICY = 65536
LAUNCH_TIMEOUT = 30
OUTPUT_LIMIT = 256 * 1024
PEER = struct.Struct("=iII")
IO_READY = {"ready_for_io": True}


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


@contextmanager
def receive_pipes(connection):
    descriptors = array.array("i")
    space = socket.CMSG_SPACE(2 * descriptors.itemsize)
    connection.settimeout(3)
    data, ancillary, flags, _ = connection.recvmsg(1, space, socket.MSG_CMSG_CLOEXEC)
    try:
        for level, kind, value in ancillary:
            if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                descriptors.frombytes(value[:len(value) - len(value) % descriptors.itemsize])
        if data != b"I" or flags & socket.MSG_CTRUNC or len(ancillary) != 1 or len(descriptors) != 2:
            raise ValueError("Expected a pair of anonymous pipes")
        identities = []
        for fd, mode in zip(descriptors, (os.O_RDONLY, os.O_WRONLY), strict=True):
            info = os.fstat(fd)
            access = fcntl.fcntl(fd, fcntl.F_GETFL) & (os.O_PATH | os.O_ACCMODE)
            if (not stat.S_ISFIFO(info.st_mode) or os.readlink(f"/proc/self/fd/{fd}") != f"pipe:[{info.st_ino}]"
                    or access != mode):
                raise ValueError("Unexpected interactive pipe type or direction")
            identities.append((info.st_dev, info.st_ino))
        if identities[0] == identities[1]:
            raise ValueError("Expected separate input and output pipes")
        yield tuple(descriptors)
    finally:
        for fd in descriptors:
            os.close(fd)


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
    required = {"program", "uids", "arguments"}
    for name, app in applications.items():
        if (not APPLICATION.fullmatch(name) or not isinstance(app, dict)
                or not required <= app.keys() <= required | {"interactive"}
                or type(app.get("interactive", False)) is not bool):
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
    if (not isinstance(request, dict) or set(request) not in ({"application"}, {"application", "interactive"})
            or not isinstance(request["application"], str) or not APPLICATION.fullmatch(request["application"])
            or ("interactive" in request and request["interactive"] is not True)):
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
    interactive = request.get("interactive", False)
    if interactive and not app.get("interactive", False):
        block("interactive_not_allowed")
        return
    if os.environ.get("OPENEDR_CONTAINMENT_AUDIT") == "1":
        session_id = start_audit_session(os.getuid())
        if session_id is not None:
            event["openedr_containment_audit_session"] = session_id
    options = SimpleNamespace(
        catalog=catalog, execution_volume=(filesystem, volume), program=Path(filesystem) / app["program"],
        arguments=app["arguments"], timeout=LAUNCH_TIMEOUT,
    )
    with ExitStack() as stack:
        launch_io = {}
        if interactive:
            try:
                send_message(connection, IO_READY)
                streams = stack.enter_context(receive_pipes(connection))
            except (OSError, ValueError):
                block("invalid_interactive_streams")
                return

            # EOF or additional control data ends the session. Input EOF arrives on the pipe.
            def cancelled():
                return bool(select.select([connection], [], [], 0)[0])

            launch_io.update(streams=streams, cancelled=cancelled)
        try:
            code = launch(options, event, delegated=True, reporter=report, **launch_io)
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


def forward_input(fd):
    with os.fdopen(fd, "wb") as output, suppress(OSError):
        while data := os.read(sys.stdin.fileno(), 4096):
            output.write(data)
            output.flush()


def print_output(text):
    sys.stdout.write("".join(char if char.isprintable() or char in "\n\t" else "?" for char in text))
    sys.stdout.flush()


def exchange_pipes(connection):
    with ExitStack() as stack:
        input_read, input_write = os.pipe2(os.O_CLOEXEC)
        stack.callback(os.close, input_write)
        try:
            output_read, output_write = os.pipe2(os.O_CLOEXEC)
            stack.callback(os.close, output_read)
            try:
                descriptors = array.array("i", (input_read, output_write))
                if connection.sendmsg([b"I"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)]) != 1:
                    raise OSError("Could not send interactive pipes")
            finally:
                os.close(output_write)
        finally:
            os.close(input_read)
        # The input thread owns the write end so it can signal EOF while output is still active.
        worker = threading.Thread(target=forward_input, args=(input_write,), daemon=True)
        worker.start()
        stack.pop_all()
        try:
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            remaining = OUTPUT_LIMIT
            while data := os.read(output_read, min(4096, remaining + 1)):
                if len(data) > remaining:
                    connection.shutdown(socket.SHUT_RDWR)
                    return False
                remaining -= len(data)
                print_output(decoder.decode(data))
            print_output(decoder.decode(b"", final=True))
            return True
        finally:
            os.close(output_read)


def client_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("application", help="application name from the administrator's launch policy")
    parser.add_argument("--interactive", action="store_true", help="connect standard input and plain-text output")
    options = parser.parse_args()
    if not APPLICATION.fullmatch(options.application):
        parser.error("Use a lowercase application name with letters, digits, and hyphens")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(SOCKET_PATH)
            request = {"application": options.application}
            if options.interactive:
                request["interactive"] = True
            send_message(connection, request)
            reply = receive_message(connection, LAUNCH_TIMEOUT + 10)
            if options.interactive and reply == IO_READY:
                if not exchange_pipes(connection):
                    print("Contained application exceeded the 256 KiB output limit", file=sys.stderr)
                    return LAUNCH_FAILED
                reply = receive_message(connection, LAUNCH_TIMEOUT + 10)
        if (not isinstance(reply, dict) or set(reply) != {"decision", "reason", "event_id", "exit_code"}
                or reply["decision"] not in ("blocked", "isolated")
                or not isinstance(reply["reason"], str) or not re.fullmatch(r"[a-z_]{1,64}", reply["reason"])
                or not isinstance(reply["event_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", reply["event_id"])
                or type(reply["exit_code"]) is not int or not 0 <= reply["exit_code"] <= 255):
            raise ValueError("Invalid launch result")
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RecursionError):
        print("Launch service unavailable or request refused", file=sys.stderr)
        return LAUNCH_FAILED
    print(f"{reply['decision']} {reply['reason']} {reply['event_id']}",
          file=sys.stderr if options.interactive or reply["decision"] == "blocked" else sys.stdout)
    return reply["exit_code"]
