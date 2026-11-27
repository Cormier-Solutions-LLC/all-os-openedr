"""Apply the local verdict before launching a managed Debian program."""

import argparse
import errno
import fcntl
import json
import os
import platform
import re
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path

from .apparmor_policy import trusted_file
from .executable import file_version, inspect_descriptor, read_catalog
from .file_provenance import visible_text
from .ima_policy import IMA_ATTRIBUTE, IMA_SHA256_PREFIX, select_filesystem


BUBBLEWRAP = "/usr/bin/bwrap"
PROGRAM = "/run/openedr/program"
DOCUMENT = "/run/openedr/document"
EXPORT = "/run/openedr/export"
LAUNCH_FAILED = 125
MEMFD_NOEXEC = getattr(os, "MFD_NOEXEC_SEAL", 0x0008)  # Linux 6.3+.
IMMUTABLE_SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
STATUS_LIMIT = 4096
DEBIAN_AMD64_LIBRARIES = Path("/usr/lib/x86_64-linux-gnu")
LIBRARY_NAME = re.compile(r"lib[A-Za-z0-9_+.-]*\.so(?:\.[0-9]+)*")
GLIBC_AMD64 = (
    ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"),
    ("/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"),
    ("/usr/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libm.so.6"),
)
BASH_AMD64 = (
    ("/usr/bin/bash", "/bin/bash"),
    ("/usr/lib/x86_64-linux-gnu/libtinfo.so.6", "/lib/x86_64-linux-gnu/libtinfo.so.6"),
)
BASE_RUNTIME_NAMES = {Path(source).name for source, _ in (*GLIBC_AMD64, *BASH_AMD64)}
PYTHON_EXECUTABLE = Path("/usr/bin/python3.13")
PYTHON_STDLIB = Path("/usr/lib/python3.13")
PYTHON_LIBRARIES = (
    str(DEBIAN_AMD64_LIBRARIES / "libexpat.so.1"),
    str(DEBIAN_AMD64_LIBRARIES / "libz.so.1"),
)
SCRIPT_PATHS = {
    b"/bin/sh": "dash",
    b"/usr/bin/sh": "dash",
    b"/bin/dash": "dash",
    b"/usr/bin/dash": "dash",
    b"/bin/bash": "bash",
    b"/usr/bin/bash": "bash",
    b"/bin/python3": "python3.13",
    b"/usr/bin/python3": "python3.13",
    b"/bin/python3.13": "python3.13",
    b"/usr/bin/python3.13": "python3.13",
}
SCRIPT_NAMES = {b"sh": "dash", b"dash": "dash", b"bash": "bash", b"python3": "python3.13", b"python3.13": "python3.13"}
SCRIPT_OPTIONS = {
    "dash": (b"-e", b"-u", b"-eu", b"-ue"),
    "bash": (b"-e", b"-u", b"-eu", b"-ue"),
    "python3.13": (b"-u",),
}


def write_filter(target):
    import seccomp

    policy = seccomp.SyscallFilter(seccomp.ALLOW)
    denied = seccomp.ERRNO(errno.EPERM)
    for name in (
        "socket", "io_uring_setup", "ptrace", "process_vm_readv", "process_vm_writev",
        "pidfd_open", "pidfd_getfd", "process_madvise", "process_mrelease", "bpf", "perf_event_open",
    ):
        policy.add_rule(denied, name)
    policy.export_bpf(target)
    target.seek(0)


def namespace_status(status, code):
    status.seek(0)
    try:
        records = [json.loads(line) for line in status.read(STATUS_LIMIT).splitlines()]
    except (UnicodeError, ValueError):
        return None
    if len(records) != 2 or not all(isinstance(record, dict) for record in records):
        return None
    pid = records[0].get("child-pid")
    if type(pid) is int and pid > 0 and records[1] == {"exit-code": code}:
        return pid
    return None


def sandbox_identity(data):
    line, newline, _ = data.partition(b"\n")
    if not newline:
        return None
    try:
        record = json.loads(line)
    except (ValueError, RecursionError):
        return None
    if not isinstance(record, dict):
        return None
    pid = record.get("child-pid")
    if type(pid) is not int or not 0 < pid < 2**31:
        return None
    identity = {"openedr_containment_pid": pid}
    namespace = record.get("pid-namespace")
    if type(namespace) is int and 0 < namespace < 2**63:
        identity["openedr_containment_pid_namespace"] = namespace
    return identity


class ClientDisconnected(Exception):
    """The local client ended an interactive launch session."""


def run_backend(command, descriptors, status_fd, timeout, on_created, *, streams=None, cancelled=None):
    def observe(identity):
        with suppress(OSError):
            on_created(identity)

    observer = None
    stdin, stdout = streams if streams is not None else (subprocess.DEVNULL, subprocess.DEVNULL)
    try:
        if cancelled is not None and cancelled():
            raise ClientDisconnected
        spawn_ns = time.monotonic_ns()
        with subprocess.Popen(
            command, stdin=stdin, stdout=stdout, stderr=stdout,
            pass_fds=descriptors, env={"PATH": "/usr/bin"},
        ) as process:
            deadline = time.monotonic() + timeout
            identity = None
            try:
                while process.poll() is None:
                    if cancelled is not None and cancelled():
                        raise ClientDisconnected
                    identity = sandbox_identity(os.pread(status_fd, STATUS_LIMIT, 0))
                    if identity is not None:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    time.sleep(min(0.05, remaining))
                if identity is None:
                    # A short-lived child can write the status and exit between reads.
                    identity = sandbox_identity(os.pread(status_fd, STATUS_LIMIT, 0))
                if identity is not None:
                    identity.update({
                        "openedr_containment_monitor_pid": process.pid,
                        "openedr_containment_fork_after_ns": spawn_ns,
                        "openedr_containment_fork_before_ns": time.monotonic_ns(),
                    })
                    worker = threading.Thread(target=observe, args=(identity,))
                    worker.start()
                    observer = worker
                if cancelled is None:
                    return process.wait(timeout=max(0, deadline - time.monotonic()))
                while process.poll() is None:
                    if cancelled():
                        raise ClientDisconnected
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    time.sleep(min(0.05, remaining))
                if cancelled():
                    raise ClientDisconnected
                return process.returncode
            finally:
                if process.poll() is None:
                    process.kill()
    finally:
        # The subprocess is gone before waiting for the audit sink. Preserve record order.
        if observer is not None:
            observer.join()


def script_runtime(snapshot):
    snapshot.seek(0)
    line = snapshot.readline(256)
    if not line.startswith(b"#!") or not line.endswith(b"\n") or any(
        value < 32 and value not in (9, 10) for value in line
    ):
        return None
    fields = line[2:-1].split()
    if not fields:
        return None
    interpreter, *options = fields
    if interpreter in (b"/usr/bin/env", b"/bin/env"):
        if len(options) >= 2 and options[0] == b"-S":
            interpreter, *options = options[1:]
        elif len(options) == 1:
            interpreter, options = options[0], []
        else:
            return None
        runtime = SCRIPT_NAMES.get(interpreter)
    else:
        runtime = SCRIPT_PATHS.get(interpreter)
    if runtime is None or len(options) > 1 or any(option not in SCRIPT_OPTIONS[runtime] for option in options):
        return None
    return runtime, tuple(option.decode("ascii") for option in options)


def valid_runtime_libraries(values):
    return (isinstance(values, list) and len(values) <= 16
            and all(isinstance(value, str) and len(value) <= 255
                    and value == str(DEBIAN_AMD64_LIBRARIES / Path(value).name)
                    and LIBRARY_NAME.fullmatch(Path(value).name)
                    and Path(value).name not in BASE_RUNTIME_NAMES for value in values)
            and len(set(values)) == len(values))


def runtime_library_bindings(libraries):
    if platform.machine() != "x86_64":
        raise ValueError("Additional libraries require Debian amd64")
    directory = DEBIAN_AMD64_LIBRARIES
    if directory.resolve(strict=True) != directory:
        raise ValueError("The runtime library directory must be canonical")
    trusted_file(directory)
    bindings = []
    for requested in libraries:
        path = Path(requested)
        source = path.resolve(strict=True)
        if (path.lstat().st_uid != 0 or source.parent != directory
                or not LIBRARY_NAME.fullmatch(source.name) or not source.is_file()):
            raise ValueError("The runtime library must be a root-owned Debian shared object")
        trusted_file(source)
        bindings.extend(("--ro-bind", str(source), requested))
    return bindings


def python_runtime_bindings():
    for path in (PYTHON_EXECUTABLE, PYTHON_STDLIB):
        if path.resolve(strict=True) != path:
            raise ValueError("The Debian Python runtime must use canonical paths")
        trusted_file(path)
    if not PYTHON_EXECUTABLE.is_file() or not PYTHON_STDLIB.is_dir():
        raise ValueError("The Debian Python runtime requires an interpreter and standard library")
    return ["--ro-bind", str(PYTHON_EXECUTABLE), str(PYTHON_EXECUTABLE),
            "--ro-bind", str(PYTHON_STDLIB), str(PYTHON_STDLIB)]


def sandbox(snapshot, arguments, timeout, script, on_created, *, streams=None, document=None, export=None, cancelled=None,
            libraries=()):
    bindings = []
    python = script is not None and script[0] == "python3.13"
    if python:
        try:
            bindings = python_runtime_bindings()
        except (OSError, ValueError, RuntimeError):
            return LAUNCH_FAILED, "python_runtime_unavailable", None
        libraries = dict.fromkeys((*PYTHON_LIBRARIES, *libraries))
    if libraries:
        try:
            bindings.extend(runtime_library_bindings(libraries))
        except (OSError, ValueError, RuntimeError):
            return LAUNCH_FAILED, "runtime_library_unavailable", None
    snapshot.flush()
    snapshot.seek(0)
    fd = snapshot.fileno()
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & IMMUTABLE_SEALS != IMMUTABLE_SEALS:
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, IMMUTABLE_SEALS)
    status_fd = os.memfd_create("openedr-sandbox-status", os.MFD_CLOEXEC | MEMFD_NOEXEC)
    with os.fdopen(status_fd, "rb") as status, os.fdopen(
        os.memfd_create("openedr-sandbox-filter", os.MFD_CLOEXEC | MEMFD_NOEXEC), "w+b",
    ) as filter_file:
        try:
            write_filter(filter_file)
        except ImportError:
            return LAUNCH_FAILED, "sandbox_filter_unavailable", None
        filter_fd = filter_file.fileno()
        runtime = GLIBC_AMD64 if platform.machine() == "x86_64" else ()
        shell_setup = []
        permissions = "0555"
        entrypoint = [PROGRAM]
        if python:
            permissions = "0444"
            entrypoint = [str(PYTHON_EXECUTABLE), "-I", "-S", "-B", "-u", "--", PROGRAM]
        elif script is not None:
            shell, options = script
            permissions = "0444"
            runtime += (("/usr/bin/dash", "/bin/dash"),)
            shell_setup = ["--setenv", "PATH", "/bin", "--symlink", "dash", "/bin/sh"]
            startup = []
            if shell == "bash":
                runtime += BASH_AMD64
                startup = ["--noprofile", "--norc"]
            entrypoint = [f"/bin/{shell}", *startup, *options, "--", PROGRAM]
        for source, destination in runtime:
            path = Path(source)
            trusted_file(path)
            if not path.is_file():
                raise ValueError("The sandbox requires a regular runtime file")
            bindings.extend(("--ro-bind", source, destination))
        descriptors = (fd, status_fd, filter_fd)
        if document is not None:
            bindings.extend(("--perms", "0444", "--ro-bind-data", str(document), DOCUMENT))
            descriptors += (document,)
            arguments = (*arguments, DOCUMENT)
        if export is not None:
            bindings.extend(("--bind", export, EXPORT))
            arguments = (*arguments, EXPORT)
        command = [
            BUBBLEWRAP, "--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-net",
            "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--new-session", "--die-with-parent",
            "--cap-drop", "ALL", "--clearenv", "--setenv", "HOME", "/tmp", "--chdir", "/tmp",
            "--size", "67108864", "--perms", "01777", "--tmpfs", "/tmp", "--dev", "/dev",
            "--perms", permissions, "--ro-bind-data", str(fd), PROGRAM, *bindings, *shell_setup,
            "--remount-ro", "/", "--seccomp", str(filter_fd), "--json-status-fd", str(status_fd),
            "--", *entrypoint, *arguments,
        ]
        try:
            code = run_backend(command, descriptors, status_fd, timeout, on_created,
                               streams=streams, cancelled=cancelled)
        except ClientDisconnected:
            return LAUNCH_FAILED, "client_disconnected", None
        except subprocess.TimeoutExpired:
            return LAUNCH_FAILED, "sandbox_timeout", None
        except OSError:
            return LAUNCH_FAILED, "sandbox_backend_unavailable", None
        pid = namespace_status(status, code)
        if pid is None:
            return LAUNCH_FAILED, "sandbox_failed", None
        return code, "isolated", pid


def trusted_location(path, metadata):
    try:
        trusted_file(path)
        current = path.stat()
    except (OSError, ValueError):
        return False
    return (
        metadata.st_uid == 0 and not metadata.st_mode & 0o022
        and (metadata.st_dev, metadata.st_ino) == (current.st_dev, current.st_ino)
        and file_version(metadata) == file_version(current)
    )


def has_volume_approval(fd, digest):
    try:
        approval = os.getxattr(fd, IMA_ATTRIBUTE)
    except OSError:
        return False
    return approval == IMA_SHA256_PREFIX + bytes.fromhex(digest)


def write_record(event):
    print(json.dumps({
        **event,
        "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
    }, separators=(",", ":")), file=sys.stderr, flush=True)


def emit(event, decision, reason, **details):
    write_record({
        **event,
        "openedr_containment_decision": decision,
        "openedr_containment_reason": reason,
        **details,
    })


def load_launch_catalog(path, event, report):
    try:
        catalog = Path(path).resolve(strict=True)
        trusted_file(catalog)
        catalog_id, verdicts = read_catalog(catalog)
    except (OSError, RuntimeError, ValueError):
        catalog_id, verdicts = None, {}
    if catalog_id is None:
        report(event, "blocked", "catalog_unavailable")
        return None
    event["openedr_executable_catalog_sha256"] = catalog_id
    return verdicts


def check_verdict(event, verdicts, report, *, path=None):
    digest = event.get("openedr_executable_sha256")
    kind = event.get("openedr_executable_format")
    if digest is None or kind not in ("elf", "script"):
        report(event, "blocked", "unsupported_program")
        return False
    if path is not None and kind == "elf" and not os.access(path, os.X_OK):
        report(event, "blocked", "file_not_executable")
        return False
    verdict = verdicts.get(digest, "unknown")
    event["openedr_executable_verdict"] = verdict
    if verdict == "untrusted":
        report(event, "blocked", "catalog_denied")
        return False
    return True


def contain_snapshot(snapshot, options, event, report, *, delegated, streams=None, document=None, export=None,
                     cancelled=None, libraries=()):
    script = None
    if event["openedr_executable_format"] == "script":
        script = script_runtime(snapshot) if platform.machine() == "x86_64" else None
        if script is None:
            report(event, "blocked", "unsupported_interpreter")
            return LAUNCH_FAILED
        event["openedr_containment_interpreter"] = script[0]
        if script[0] == "python3.13" and not options.allow_python:
            report(event, "blocked", "interpreter_not_allowed")
            return LAUNCH_FAILED
    creation = {}

    def on_created(identity):
        creation.update(identity)
        write_record({
            **event, **identity,
            "openedr_event": "executable.sandbox_created",
            "openedr_event_id": uuid.uuid4().hex,
        })

    exit_code, outcome, pid = sandbox(snapshot, options.arguments, options.timeout, script, on_created,
                                      streams=streams, document=document, export=export, cancelled=cancelled,
                                      libraries=libraries)
    details = {**creation, "openedr_containment_exit_code": exit_code}
    if pid is not None:
        details["openedr_containment_pid"] = pid
        if event["openedr_executable_verdict"] == "unknown":
            reason = "catalog_unknown"
        elif delegated:
            reason = "delegated_launch"
        else:
            reason = "script_requires_isolation" if script is not None else "unmanaged_location"
        report(event, "isolated", reason, **details)
    else:
        report(event, "blocked", outcome, **details)
    return exit_code


def launch_download(snapshot, options, event, *, reporter, streams=None, cancelled=None, libraries=()):
    fd = snapshot.fileno()
    if fcntl.fcntl(fd, fcntl.F_GET_SEALS) & IMMUTABLE_SEALS != IMMUTABLE_SEALS:
        reporter(event, "blocked", "invalid_download")
        return LAUNCH_FAILED
    verdicts = load_launch_catalog(options.catalog, event, reporter)
    if verdicts is None:
        return LAUNCH_FAILED
    evidence = inspect_descriptor(fd)
    for field in ("openedr_executable_path", "openedr_executable_device", "openedr_executable_inode"):
        evidence.pop(field, None)
    event.update(evidence)
    if not check_verdict(event, verdicts, reporter):
        return LAUNCH_FAILED
    return contain_snapshot(snapshot, options, event, reporter, delegated=True, streams=streams, cancelled=cancelled,
                            libraries=libraries)


def launch(options, event, *, delegated=False, reporter=None, streams=None, document=None, export=None, cancelled=None,
           libraries=()):
    report = reporter or emit
    volume_device = None
    if delegated and options.execution_volume is None:
        report(event, "blocked", "execution_volume_unavailable")
        return LAUNCH_FAILED
    if options.execution_volume is not None:
        mount, expected = options.execution_volume
        event["openedr_executable_volume_uuid"] = expected
        try:
            root, device, identity = select_filesystem(mount)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            report(event, "blocked", "execution_volume_unavailable")
            return LAUNCH_FAILED
        if str(identity) != expected:
            report(event, "blocked", "execution_volume_mismatch")
            return LAUNCH_FAILED
        volume_device = device
    verdicts = load_launch_catalog(options.catalog, event, report)
    if verdicts is None:
        return LAUNCH_FAILED
    path = Path(options.program).resolve(strict=True)
    if volume_device is not None and not path.is_relative_to(root):
        report(event, "blocked", "execution_volume_mismatch")
        return LAUNCH_FAILED
    if delegated and (path != options.program or not path.is_file() or not trusted_location(path, path.stat())):
        report(event, "blocked", "unmanaged_location")
        return LAUNCH_FAILED
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as source:
        fd = source.fileno()
        metadata = os.fstat(fd)
        if volume_device is not None and metadata.st_dev != volume_device:
            report(event, "blocked", "execution_volume_mismatch")
            return LAUNCH_FAILED
        if delegated and not trusted_location(path, metadata):
            report(event, "blocked", "unmanaged_location")
            return LAUNCH_FAILED
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
                or os.fstatvfs(fd).f_flag & os.ST_NOEXEC):
            report(event, "blocked", "file_not_executable")
            return LAUNCH_FAILED
        copy_fd = os.memfd_create("openedr-program", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MEMFD_NOEXEC)
        with os.fdopen(copy_fd, "w+b") as snapshot:
            event.update(inspect_descriptor(fd, snapshot=snapshot))
            if not check_verdict(event, verdicts, report, path=path):
                return LAUNCH_FAILED
            if (not delegated and document is None and export is None and event["openedr_executable_format"] == "elf"
                    and event["openedr_executable_verdict"] == "trusted"
                    and trusted_location(path, metadata)
                    and file_version(metadata) == file_version(os.fstat(fd))):
                if volume_device is not None and not has_volume_approval(fd, event["openedr_executable_sha256"]):
                    report(event, "blocked", "ima_approval_missing")
                    return LAUNCH_FAILED
                report(event, "approved", "catalog_trusted")
                try:
                    os.execve(fd, [str(path), *options.arguments], os.environ)
                except OSError:
                    report({**event, "openedr_event_id": uuid.uuid4().hex}, "blocked", "native_exec_failed")
                    return LAUNCH_FAILED
            return contain_snapshot(snapshot, options, event, report, delegated=delegated, streams=streams,
                                    document=document, export=export, cancelled=cancelled, libraries=libraries)


def launch_event(program=None):
    launch_id = uuid.uuid4().hex
    event = {
        "openedr_source": "all-os-openedr",
        "openedr_schema": 1,
        "openedr_event": "executable.launch_decision",
        "openedr_event_id": launch_id,
        "openedr_containment_launch_id": launch_id,
        "openedr_host": socket.gethostname(),
        "openedr_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "openedr_pid": os.getpid(),
        "openedr_uid": os.getuid(),
    }
    if program is not None:
        event["openedr_executable_path"] = visible_text(os.fsencode(program))
    return event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, help="administrator-owned SHA-256 verdict catalog")
    parser.add_argument("--execution-volume", nargs=2, metavar=("MOUNT", "UUID"),
                        help="bind launches to a dedicated ext4 execution volume and require IMA approval for native execution")
    parser.add_argument("--timeout", type=int, metavar="SECONDS", default=30)
    parser.add_argument("--allow-python", action="store_true", help="allow contained Debian Python 3.13 scripts")
    parser.add_argument("program", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        parser.error("Run under a dedicated unprivileged account")
    if not options.program.is_absolute() or not Path(options.catalog).is_absolute():
        parser.error("Use absolute paths for the program and catalog")
    if options.execution_volume is not None:
        mount, identity = options.execution_volume
        if not Path(mount).is_absolute():
            parser.error("Use an absolute mount path for the execution volume")
        try:
            options.execution_volume = mount, str(uuid.UUID(identity))
        except ValueError:
            parser.error("Supply the execution volume's filesystem UUID")
    if not 1 <= options.timeout <= 300:
        parser.error("Use a timeout between 1 and 300 seconds")
    event = launch_event(options.program)
    try:
        return launch(options, event)
    except (OSError, RuntimeError, ValueError):
        emit(event, "blocked", "launch_failed")
        return LAUNCH_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
