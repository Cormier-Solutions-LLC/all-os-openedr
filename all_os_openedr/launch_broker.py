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
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from types import SimpleNamespace

from .apparmor_policy import trusted_file
from .containment import (
    IMMUTABLE_SEALS, LAUNCH_FAILED, MEMFD_NOEXEC, emit, launch, launch_download, launch_event, sandbox,
    valid_runtime_libraries,
)
from .executable import MAX_EXECUTABLE_SIZE, file_version, read_catalog
from .ima_policy import select_filesystem
from .ima_probe import check_ima
from .sandbox_audit import start_audit_session


SOCKET_PATH = "/run/all-os-openedr-launch.sock"
POLICY_PATH = Path("/etc/all-os-openedr-launch.json")
EXPORT_DIRECTORY = "/run/all-os-openedr-export"
APPLICATION = re.compile(r"[a-z][a-z0-9-]{0,63}")
MAX_MESSAGE = 4096
MAX_POLICY = 65536
LAUNCH_TIMEOUT = 30
OUTPUT_LIMIT = 256 * 1024
DOCUMENT_LIMIT = 8 * 1024 * 1024
DOCUMENT_LENGTH = struct.Struct("!I")
DOWNLOAD_TIMEOUT = 15
PEER = struct.Struct("=iII")
IO_READY = {"ready_for_io": True}
IO_OPTIONS = ("interactive", "document", "export")
HEALTH_CANARY = br"""#!/bin/sh
[ ! -e /etc/passwd ] || exit 2
printf 'probe\n' > /tmp/openedr-health || exit 3
read marker < /tmp/openedr-health || exit 4
[ "$marker" = probe ] || exit 5
exit 37
"""
HEALTH_RESULTS = frozenset({
    "ready", "policy_invalid", "catalog_invalid", "execution_volume_unavailable", "execution_volume_mismatch",
    "sandbox_backend_unavailable", "sandbox_filter_unavailable", "sandbox_timeout", "sandbox_failed",
    "runtime_unavailable", "canary_failed",
})


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


def read_local_file(path, limit):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("Expected a regular file within the size limit")
        data = stream.read(limit + 1)
    if data is None or len(data) > limit:
        raise ValueError("File could not be read within the size limit")
    return data


def receive_chunks(connection, size, deadline):
    while size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("File transfer expired")
        connection.settimeout(remaining)
        chunk = connection.recv(min(size, 65536))
        if not chunk:
            raise ValueError("Incomplete file transfer")
        size -= len(chunk)
        yield chunk


@contextmanager
def receive_snapshot(connection, *, limit, name, timeout):
    deadline = time.monotonic() + timeout
    header = b"".join(receive_chunks(connection, DOCUMENT_LENGTH.size, deadline))
    size, = DOCUMENT_LENGTH.unpack(header)
    if size > limit:
        raise ValueError("File exceeds the size limit")
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MEMFD_NOEXEC)
    with os.fdopen(fd, "w+b") as snapshot:
        for chunk in receive_chunks(connection, size, deadline):
            snapshot.write(chunk)
        snapshot.flush()
        snapshot.seek(0)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, IMMUTABLE_SEALS)
        yield snapshot


def send_snapshot(connection, data, timeout):
    connection.settimeout(timeout)
    connection.sendall(DOCUMENT_LENGTH.pack(len(data)))
    connection.sendall(data)


def read_export(fd):
    before = os.fstat(fd)
    if before.st_size > DOCUMENT_LIMIT:
        raise ValueError("Export exceeds the size limit")
    data = os.pread(fd, DOCUMENT_LIMIT + 1, 0)
    if len(data) != before.st_size or file_version(before) != file_version(os.fstat(fd)):
        raise ValueError("Export changed while being read")
    return data


def save_export(connection, path, size):
    directory = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        flags = os.O_TMPFILE | os.O_WRONLY | os.O_CLOEXEC
        with os.fdopen(os.open(".", flags, 0o600, dir_fd=directory), "wb") as output:
            connection.settimeout(3)
            connection.sendall(b"E")
            for chunk in receive_chunks(connection, size, time.monotonic() + 3):
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
            os.link(f"/proc/self/fd/{output.fileno()}", path.name, dst_dir_fd=directory, follow_symlinks=True)
    finally:
        os.close(directory)


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


def valid_uids(uids):
    return isinstance(uids, list) and all(type(uid) is int and 0 < uid < 0xFFFFFFFF for uid in uids)


def parse_policy(value):
    base = {"schema", "catalog"}
    staged = {"filesystem", "uuid", "applications"}
    download_settings = {"download_uids", "download_libraries", "download_python"}
    if (not isinstance(value, dict) or not base <= value.keys() <= base | staged | download_settings
            or type(value["schema"]) is not int or value["schema"] != 1):
        raise ValueError("Invalid launch policy schema")
    catalog = value["catalog"]
    if not isinstance(catalog, str) or not Path(catalog).is_absolute() or "\0" in catalog:
        raise ValueError("The catalog path must be absolute")
    download_uids = value.get("download_uids", [])
    if not valid_uids(download_uids):
        raise ValueError("Invalid download caller UIDs")
    download_libraries = value.get("download_libraries", [])
    if not valid_runtime_libraries(download_libraries):
        raise ValueError("Invalid download runtime libraries")
    download_python = value.get("download_python", False)
    if type(download_python) is not bool:
        raise ValueError("Invalid download Python permission")
    download_app = {
        "uids": download_uids, "interactive": True, "arguments": (),
        "libraries": download_libraries, "python": download_python,
    }
    if not staged.intersection(value):
        return None, None, catalog, {}, download_app
    if not staged <= value.keys():
        raise ValueError("Incomplete staged application policy")
    filesystem = value["filesystem"]
    if not isinstance(filesystem, str) or not Path(filesystem).is_absolute() or "\0" in filesystem:
        raise ValueError("The filesystem path must be absolute")
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
                or not required <= app.keys() <= required.union(IO_OPTIONS, {"libraries", "python"})
                or any(type(app.get(key, False)) is not bool for key in (*IO_OPTIONS, "python"))):
            raise ValueError("Invalid application policy")
        if not valid_runtime_libraries(app.get("libraries", [])):
            raise ValueError("Invalid application runtime libraries")
        program, uids, arguments = app["program"], app["uids"], app["arguments"]
        if (not isinstance(program, str) or "\0" in program or not Path(program).parts
                or Path(program).is_absolute() or ".." in Path(program).parts):
            raise ValueError("Application paths must be relative to the execution volume")
        if not valid_uids(uids):
            raise ValueError("Invalid application caller UIDs")
        if (not isinstance(arguments, list) or len(arguments) > 16
                or any(not isinstance(arg, str) or "\0" in arg or len(arg.encode("utf-8")) > 256 for arg in arguments)):
            raise ValueError("Invalid application arguments")
    return filesystem, str(volume), catalog, applications, download_app


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


def probe_broker():
    try:
        filesystem, volume, catalog, _, _ = read_policy()
    except (OSError, ValueError, RuntimeError):
        return {"broker": "policy_invalid", "ima": "unknown"}
    ima = "execution_volume_unconfigured"
    if filesystem is not None:
        try:
            root, device, identity = select_filesystem(filesystem)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            return {"broker": "execution_volume_unavailable", "ima": "execution_volume_unavailable"}
        if str(identity) != volume:
            return {"broker": "execution_volume_mismatch", "ima": "execution_volume_unavailable"}
        ima = check_ima(root, device)
    if read_catalog(catalog)[0] is None:
        return {"broker": "catalog_invalid", "ima": ima}
    try:
        descriptor = os.memfd_create("openedr-health", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MEMFD_NOEXEC)
        with os.fdopen(descriptor, "w+b") as snapshot:
            snapshot.write(HEALTH_CANARY)
            code, reason, pid = sandbox(snapshot, (), 6, ("dash", ()), lambda _: None)
    except (OSError, ValueError, RuntimeError):
        return {"broker": "runtime_unavailable", "ima": ima}
    if pid is None:
        broker = reason if reason in HEALTH_RESULTS else "runtime_unavailable"
    else:
        broker = "ready" if reason == "isolated" and code == 37 else "canary_failed"
    return {"broker": broker, "ima": ima}


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
    if not isinstance(request, dict):
        block("invalid_request")
        return
    if request.keys() == {"health"} and request["health"] is True:
        if uid != 0:
            block("request_not_authorized")
        else:
            send_message(connection, probe_broker())
        return
    download = "download" in request
    name = request.get("application")
    if download:
        valid = request.keys() <= {"download", "interactive"} and request["download"] is True
    else:
        valid = (request.keys() <= {"application", *IO_OPTIONS} and isinstance(name, str)
                 and APPLICATION.fullmatch(name))
    if not valid or any(request.get(key, True) is not True for key in IO_OPTIONS):
        block("invalid_request")
        return
    try:
        filesystem, volume, catalog, applications, download_app = read_policy()
    except (OSError, ValueError, RuntimeError):
        block("launch_policy_unavailable")
        return
    app = download_app if download else applications.get(name)
    if app is None or uid == os.getuid() or uid not in app["uids"]:
        block("request_not_authorized")
        return
    event["openedr_containment_application"] = "downloaded file" if download else name
    requested = request.keys() - {"application", "download"}
    for key in IO_OPTIONS:
        if key in requested and not app.get(key, False):
            block(f"{key}_not_allowed")
            return
    if os.environ.get("OPENEDR_CONTAINMENT_AUDIT") == "1":
        session_id = start_audit_session(os.getuid())
        if session_id is not None:
            event["openedr_containment_audit_session"] = session_id
    options = SimpleNamespace(
        catalog=catalog, arguments=app["arguments"], timeout=LAUNCH_TIMEOUT, allow_python=app.get("python", False),
    )
    if not download:
        options.execution_volume = filesystem, volume
        options.program = Path(filesystem) / app["program"]
    exported = None
    with ExitStack() as stack:
        launch_io = {"libraries": app.get("libraries", ())}
        if download or requested:
            send_message(connection, IO_READY)

            # EOF or additional control data ends the session. Input EOF arrives on the pipe.
            def cancelled():
                return bool(select.select([connection], [], [], 0)[0])

            launch_io["cancelled"] = cancelled
        if download:
            try:
                snapshot = stack.enter_context(receive_snapshot(
                    connection, limit=MAX_EXECUTABLE_SIZE, name="openedr-download", timeout=DOWNLOAD_TIMEOUT,
                ))
            except (OSError, ValueError):
                block("invalid_download")
                return
        if "document" in requested:
            try:
                document = stack.enter_context(receive_snapshot(
                    connection, limit=DOCUMENT_LIMIT, name="openedr-document", timeout=3,
                ))
                launch_io["document"] = document.fileno()
            except (OSError, ValueError):
                block("invalid_document")
                return
        if "interactive" in requested:
            try:
                launch_io["streams"] = stack.enter_context(receive_pipes(connection))
            except (OSError, ValueError):
                block("invalid_interactive_streams")
                return
        target = None
        if "export" in requested:
            try:
                target = stack.enter_context(tempfile.NamedTemporaryFile(dir=EXPORT_DIRECTORY))
            except OSError:
                block("export_unavailable")
                return
            launch_io["export"] = target.name
        try:
            if download:
                code = launch_download(snapshot, options, event, reporter=report, **launch_io)
            else:
                code = launch(options, event, delegated=True, reporter=report, **launch_io)
        except (OSError, ValueError, RuntimeError):
            block("launch_failed")
            return
        if target is not None and code == 0 and reply.get("decision") == "isolated":
            try:
                exported = read_export(target.fileno())
            except (ValueError, OSError):
                reply["reason"] = "export_unavailable"
                code = LAUNCH_FAILED
            else:
                reply["export_size"] = len(exported)
    send_message(connection, {**reply, "exit_code": code})
    if exported is not None and connection.recv(1) == b"E":
        connection.sendall(exported)


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


def validate_reply(reply, export_requested):
    fields = {"decision", "reason", "event_id", "exit_code"}
    if not isinstance(reply, dict):
        raise ValueError("Invalid launch result")
    if export_requested and reply.get("decision") == "isolated" and reply.get("exit_code") == 0:
        fields.add("export_size")
    if (set(reply) != fields or reply["decision"] not in ("blocked", "isolated")
            or not isinstance(reply["reason"], str) or not re.fullmatch(r"[a-z_]{1,64}", reply["reason"])
            or not isinstance(reply["event_id"], str) or not re.fullmatch(r"[a-f0-9]{32}", reply["event_id"])
            or type(reply["exit_code"]) is not int or not 0 <= reply["exit_code"] <= 255):
        raise ValueError("Invalid launch result")
    if "export_size" in fields and (type(reply["export_size"]) is not int or not 0 <= reply["export_size"] <= DOCUMENT_LIMIT):
        raise ValueError("Invalid export size")


def client_main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("application", nargs="?", help="application name from the administrator's launch policy")
    parser.add_argument("--download", type=Path, help="run a selected local executable in containment")
    parser.add_argument("--interactive", action="store_true", help="connect standard input and plain-text output")
    parser.add_argument("--document", type=Path, help="provide a read-only copy of a selected local file")
    parser.add_argument("--export", type=Path, help="save a successful export as a new local file")
    options = parser.parse_args()
    if (options.application is None) == (options.download is None):
        parser.error("Choose an enrolled application or use --download FILE")
    if options.download is not None and (options.document is not None or options.export is not None):
        parser.error("Document and export options require an enrolled application")
    if options.application is not None and not APPLICATION.fullmatch(options.application):
        parser.error("Use a lowercase application name with letters, digits, and hyphens")
    try:
        document = None
        download = None
        if options.download is not None:
            try:
                download = read_local_file(options.download, MAX_EXECUTABLE_SIZE)
            except (OSError, ValueError):
                print("Could not read a regular program up to 32 MiB", file=sys.stderr)
                return LAUNCH_FAILED
        if options.document is not None:
            try:
                document = read_local_file(options.document, DOCUMENT_LIMIT)
            except (OSError, ValueError):
                print("Could not read a regular document up to 8 MiB", file=sys.stderr)
                return LAUNCH_FAILED
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(SOCKET_PATH)
            request = {"download": True} if download is not None else {"application": options.application}
            if options.interactive:
                request["interactive"] = True
            if document is not None:
                request["document"] = True
            if options.export is not None:
                request["export"] = True
            send_message(connection, request)
            reply = receive_message(connection, LAUNCH_TIMEOUT + 10)
            if (download is not None or len(request) > 1) and reply == IO_READY:
                if download is not None:
                    send_snapshot(connection, download, DOWNLOAD_TIMEOUT)
                if document is not None:
                    send_snapshot(connection, document, 3)
                if options.interactive and not exchange_pipes(connection):
                    print("Contained application exceeded the 256 KiB output limit", file=sys.stderr)
                    return LAUNCH_FAILED
                reply = receive_message(connection, LAUNCH_TIMEOUT + 10)
            validate_reply(reply, options.export is not None)
            if "export_size" in reply:
                try:
                    save_export(connection, options.export, reply["export_size"])
                except (OSError, ValueError):
                    print("Could not save the export as a new local file", file=sys.stderr)
                    return LAUNCH_FAILED
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, RecursionError):
        print("Launch service unavailable or request refused", file=sys.stderr)
        return LAUNCH_FAILED
    print(f"{reply['decision']} {reply['reason']} {reply['event_id']}",
          file=sys.stderr if options.interactive or reply["decision"] == "blocked" else sys.stdout)
    return reply["exit_code"]
