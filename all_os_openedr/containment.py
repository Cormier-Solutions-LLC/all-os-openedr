"""Apply the local verdict before launching a managed Debian program."""

import argparse
import errno
import fcntl
import json
import os
import platform
import socket
import stat
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .apparmor_policy import trusted_file
from .executable import file_version, inspect_descriptor, read_catalog
from .file_provenance import visible_text
from .ima_policy import IMA_ATTRIBUTE, IMA_SHA256_PREFIX, select_filesystem


BUBBLEWRAP = "/usr/bin/bwrap"
PROGRAM = "/run/openedr/program"
LAUNCH_FAILED = 125
MEMFD_NOEXEC = getattr(os, "MFD_NOEXEC_SEAL", 0x0008)  # Linux 6.3+.
GLIBC_AMD64 = (
    ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"),
    ("/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"),
    ("/usr/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libm.so.6"),
)
SHELL_PATHS = {
    b"/bin/sh": "dash",
    b"/usr/bin/sh": "dash",
    b"/bin/dash": "dash",
    b"/usr/bin/dash": "dash",
    b"/bin/bash": "bash",
    b"/usr/bin/bash": "bash",
}
SHELL_NAMES = {b"sh": "dash", b"dash": "dash", b"bash": "bash"}
SHELL_OPTIONS = (b"-e", b"-u", b"-eu", b"-ue")


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
        records = [json.loads(line) for line in status.read(4096).splitlines()]
    except (UnicodeError, ValueError):
        return None
    if len(records) != 2 or not all(isinstance(record, dict) for record in records):
        return None
    pid = records[0].get("child-pid")
    if type(pid) is int and pid > 0 and records[1] == {"exit-code": code}:
        return pid
    return None


def script_shell(snapshot):
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
        shell = SHELL_NAMES.get(interpreter)
    else:
        shell = SHELL_PATHS.get(interpreter)
    if shell is None or len(options) > 1 or any(option not in SHELL_OPTIONS for option in options):
        return None
    return shell, tuple(option.decode("ascii") for option in options)


def sandbox(snapshot, arguments, timeout, script=None):
    snapshot.flush()
    snapshot.seek(0)
    fd = snapshot.fileno()
    seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
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
        if script is not None:
            shell, options = script
            permissions = "0444"
            runtime += (("/usr/bin/dash", "/bin/dash"),)
            shell_setup = ["--setenv", "PATH", "/bin", "--symlink", "dash", "/bin/sh"]
            startup = []
            if shell == "bash":
                runtime += (
                    ("/usr/bin/bash", "/bin/bash"),
                    ("/usr/lib/x86_64-linux-gnu/libtinfo.so.6", "/lib/x86_64-linux-gnu/libtinfo.so.6"),
                )
                startup = ["--noprofile", "--norc"]
            entrypoint = [f"/bin/{shell}", *startup, *options, "--", PROGRAM]
        bindings = []
        for source, destination in runtime:
            path = Path(source)
            trusted_file(path)
            if not path.is_file():
                raise ValueError("The sandbox requires a regular runtime file")
            bindings.extend(("--ro-bind", source, destination))
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
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(fd, status_fd, filter_fd), env={"PATH": "/usr/bin"}, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return LAUNCH_FAILED, "sandbox_timeout", None
        except OSError:
            return LAUNCH_FAILED, "sandbox_backend_unavailable", None
        pid = namespace_status(status, result.returncode)
        if pid is None:
            return LAUNCH_FAILED, "sandbox_failed", None
        return result.returncode, "isolated", pid


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


def emit(event, decision, reason, **details):
    print(json.dumps({
        **event,
        "openedr_containment_decision": decision,
        "openedr_containment_reason": reason,
        **details,
    }, separators=(",", ":")), file=sys.stderr, flush=True)


def launch(options, event):
    volume_device = None
    if options.execution_volume is not None:
        mount, expected = options.execution_volume
        event["openedr_executable_volume_uuid"] = expected
        try:
            root, device, identity = select_filesystem(mount)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            emit(event, "blocked", "execution_volume_unavailable")
            return LAUNCH_FAILED
        if str(identity) != expected:
            emit(event, "blocked", "execution_volume_mismatch")
            return LAUNCH_FAILED
        volume_device = device
    try:
        catalog = Path(options.catalog).resolve(strict=True)
        trusted_file(catalog)
        catalog_id, verdicts = read_catalog(catalog)
    except (OSError, RuntimeError, ValueError):
        catalog_id, verdicts = None, {}
    if catalog_id is None:
        emit(event, "blocked", "catalog_unavailable")
        return LAUNCH_FAILED
    event["openedr_executable_catalog_sha256"] = catalog_id
    path = Path(options.program).resolve(strict=True)
    if volume_device is not None and not path.is_relative_to(root):
        emit(event, "blocked", "execution_volume_mismatch")
        return LAUNCH_FAILED
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as source:
        fd = source.fileno()
        metadata = os.fstat(fd)
        if volume_device is not None and metadata.st_dev != volume_device:
            emit(event, "blocked", "execution_volume_mismatch")
            return LAUNCH_FAILED
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
                or os.fstatvfs(fd).f_flag & os.ST_NOEXEC):
            emit(event, "blocked", "file_not_executable")
            return LAUNCH_FAILED
        copy_fd = os.memfd_create("openedr-program", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MEMFD_NOEXEC)
        with os.fdopen(copy_fd, "w+b") as snapshot:
            event.update(inspect_descriptor(fd, snapshot=snapshot))
            digest = event.get("openedr_executable_sha256")
            kind = event.get("openedr_executable_format")
            if digest is None or kind not in ("elf", "script"):
                emit(event, "blocked", "unsupported_program")
                return LAUNCH_FAILED
            if kind == "elf" and not os.access(path, os.X_OK):
                emit(event, "blocked", "file_not_executable")
                return LAUNCH_FAILED
            verdict = verdicts.get(digest, "unknown")
            event["openedr_executable_verdict"] = verdict
            if verdict == "untrusted":
                emit(event, "blocked", "catalog_denied")
                return LAUNCH_FAILED
            script = None
            if kind == "script":
                script = script_shell(snapshot) if platform.machine() == "x86_64" else None
                if script is None:
                    emit(event, "blocked", "unsupported_interpreter")
                    return LAUNCH_FAILED
                event["openedr_containment_interpreter"] = script[0]
            if (script is None and verdict == "trusted" and trusted_location(path, metadata)
                    and file_version(metadata) == file_version(os.fstat(fd))):
                if volume_device is not None and not has_volume_approval(fd, digest):
                    emit(event, "blocked", "ima_approval_missing")
                    return LAUNCH_FAILED
                emit(event, "approved", "catalog_trusted")
                try:
                    os.execve(fd, [str(path), *options.arguments], os.environ)
                except OSError:
                    emit({**event, "openedr_event_id": uuid.uuid4().hex}, "blocked", "native_exec_failed")
                    return LAUNCH_FAILED
            exit_code, outcome, pid = sandbox(snapshot, options.arguments, options.timeout, script)
            details = {"openedr_containment_exit_code": exit_code}
            if pid is not None:
                details["openedr_containment_pid"] = pid
                if verdict == "unknown":
                    reason = "catalog_unknown"
                else:
                    reason = "script_requires_isolation" if script is not None else "unmanaged_location"
                emit(event, "isolated", reason, **details)
            else:
                emit(event, "blocked", outcome, **details)
            return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, help="administrator-owned SHA-256 verdict catalog")
    parser.add_argument("--execution-volume", nargs=2, metavar=("MOUNT", "UUID"),
                        help="bind launches to a dedicated ext4 execution volume and require IMA approval for native execution")
    parser.add_argument("--timeout", type=int, metavar="SECONDS", default=30)
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
    event = {
        "openedr_source": "all-os-openedr",
        "openedr_schema": 1,
        "openedr_event": "executable.launch_decision",
        "openedr_event_id": uuid.uuid4().hex,
        "openedr_host": socket.gethostname(),
        "openedr_boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "openedr_pid": os.getpid(),
        "openedr_uid": os.getuid(),
        "openedr_executable_path": visible_text(os.fsencode(options.program)),
    }
    try:
        return launch(options, event)
    except (OSError, RuntimeError, ValueError):
        emit(event, "blocked", "launch_failed")
        return LAUNCH_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
