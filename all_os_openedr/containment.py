"""Apply the local verdict before a managed Debian ELF launch."""

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


BUBBLEWRAP = "/usr/bin/bwrap"
PROGRAM = "/run/openedr/program"
LAUNCH_FAILED = 125
MEMFD_NOEXEC = getattr(os, "MFD_NOEXEC_SEAL", 0x0008)  # Linux 6.3+.
GLIBC_AMD64 = (
    ("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"),
    ("/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6"),
    ("/usr/lib/x86_64-linux-gnu/libm.so.6", "/lib/x86_64-linux-gnu/libm.so.6"),
)


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


def sandbox(snapshot, arguments, timeout):
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
        libraries = []
        if platform.machine() == "x86_64":
            for source, destination in GLIBC_AMD64:
                library = Path(source)
                trusted_file(library)
                if not library.is_file():
                    raise ValueError("The sandbox requires a regular glibc runtime file")
                libraries.extend(("--ro-bind", source, destination))
        command = [
            BUBBLEWRAP, "--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-net",
            "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--new-session", "--die-with-parent",
            "--cap-drop", "ALL", "--clearenv", "--setenv", "HOME", "/tmp", "--chdir", "/tmp",
            "--size", "67108864", "--perms", "01777", "--tmpfs", "/tmp", "--dev", "/dev",
            "--perms", "0555", "--ro-bind-data", str(fd), PROGRAM, *libraries, "--remount-ro", "/",
            "--seccomp", str(filter_fd), "--json-status-fd", str(status_fd), "--", PROGRAM, *arguments,
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


def emit(event, decision, reason, **details):
    print(json.dumps({
        **event,
        "openedr_containment_decision": decision,
        "openedr_containment_reason": reason,
        **details,
    }, separators=(",", ":")), file=sys.stderr, flush=True)


def launch(options, event):
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
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as source:
        fd = source.fileno()
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
                or not os.access(path, os.X_OK) or os.fstatvfs(fd).f_flag & os.ST_NOEXEC):
            emit(event, "blocked", "file_not_executable")
            return LAUNCH_FAILED
        copy_fd = os.memfd_create("openedr-program", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MEMFD_NOEXEC)
        with os.fdopen(copy_fd, "w+b") as snapshot:
            event.update(inspect_descriptor(fd, snapshot=snapshot))
            digest = event.get("openedr_executable_sha256")
            if digest is None or event.get("openedr_executable_format") != "elf":
                emit(event, "blocked", "unsupported_program")
                return LAUNCH_FAILED
            verdict = verdicts.get(digest, "unknown")
            event["openedr_executable_verdict"] = verdict
            if verdict == "untrusted":
                emit(event, "blocked", "catalog_denied")
                return LAUNCH_FAILED
            if (verdict == "trusted" and trusted_location(path, metadata)
                    and file_version(metadata) == file_version(os.fstat(fd))):
                emit(event, "approved", "catalog_trusted")
                try:
                    os.execve(fd, [str(path), *options.arguments], os.environ)
                except OSError:
                    emit({**event, "openedr_event_id": uuid.uuid4().hex}, "blocked", "native_exec_failed")
                    return LAUNCH_FAILED
            exit_code, outcome, pid = sandbox(snapshot, options.arguments, options.timeout)
            details = {"openedr_containment_exit_code": exit_code}
            if pid is not None:
                details["openedr_containment_pid"] = pid
                emit(event, "isolated", "catalog_unknown" if verdict == "unknown" else "unmanaged_location", **details)
            else:
                emit(event, "blocked", outcome, **details)
            return exit_code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, help="administrator-owned SHA-256 verdict catalog")
    parser.add_argument("--timeout", type=int, metavar="SECONDS", default=30)
    parser.add_argument("program", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    if os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        parser.error("Run under a dedicated unprivileged account")
    if not options.program.is_absolute() or not Path(options.catalog).is_absolute():
        parser.error("Use absolute paths for the program and catalog")
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
