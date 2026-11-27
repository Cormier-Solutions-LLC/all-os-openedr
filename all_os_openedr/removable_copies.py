"""Trace file transfers between two explicitly enrolled Linux mounts."""

import argparse
import ctypes
import hashlib
import json
import os
import platform
import select
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .file_provenance import checked, visible_text
from .ima_audit import append
from .removable_storage import Mount, device_evidence, mounts_from


PROGRAM = "/usr/share/all-os-openedr/storage/removable-copies.bt"
OUTPUT = Path("/var/log/all-os-openedr-removable-copies/events.jsonl")
MAX_LINE = 8192
PATH_SEPARATOR = "\n//\n"
MAX_EVENTS_PER_SECOND = 64
LOG_MAX_BYTES = 16 * 1024 * 1024
LOG_BACKUPS = 3
STATX_MNT_ID_UNIQUE = 0x4000
AT_NO_AUTOMOUNT = 0x800
METHODS = {
    "buffered": "file.copy_inferred",
    "copy_file_range": "file.copy_observed",
    "sendfile": "file.copy_observed",
}


@dataclass(frozen=True)
class Volume:
    mount: Mount
    device: int
    filesystem_uuid: str
    unique_mount_id: int
    media_id: str = ""

    def contains(self, path):
        return (
            path.startswith(self.mount.point + "/")
            and not path.endswith(" (deleted)")
            and all(part not in ("", ".", "..") for part in path.split("/")[1:])
            and "\0" not in path
        )


def mount_snapshot():
    with open("/proc/self/mountinfo", "rb") as stream:
        return {mount.point: mount for mount in mounts_from(stream)}


def unique_mount_id(path):
    # Linux statx UAPI has a 256-byte result and stx_mnt_id at offset 0x90.
    libc = ctypes.CDLL(None, use_errno=True)
    result = ctypes.create_string_buffer(256)
    checked(libc.statx(-100, os.fsencode(path), AT_NO_AUTOMOUNT, STATX_MNT_ID_UNIQUE, result), "statx")
    if not struct.unpack_from("=I", result)[0] & STATX_MNT_ID_UNIQUE:
        raise ValueError("Kernel support for unique mount IDs is required")
    return struct.unpack_from("=Q", result, 0x90)[0]


def enroll(path, mounts, context, removable):
    import pyudev

    resolved = Path(path).resolve(strict=True)
    mount = mounts.get(str(resolved))
    if not resolved.is_dir() or not mount or mount.point == "/" or mount.filesystem != "ext4":
        raise ValueError("Select an explicitly mounted ext4 volume other than the root filesystem")
    unique_id = unique_mount_id(resolved)
    number = resolved.stat().st_dev
    major, minor = os.major(number), os.minor(number)
    if mount.number != f"{major}:{minor}":
        raise ValueError("Volume identity changed during enrollment")
    device = pyudev.Devices.from_device_number(context, "block", number)
    identity = device.properties.get("ID_FS_UUID", "")
    if not identity or not device.is_initialized:
        raise ValueError("The selected filesystem needs an initialized udev UUID")
    evidence = device_evidence(device)
    if bool(evidence) != removable:
        raise ValueError("Select one fixed and one removable volume")
    if unique_mount_id(resolved) != unique_id:
        raise ValueError("Volume identity changed during enrollment")
    media_id = evidence.get("openedr_device_id", "") if evidence else ""
    return Volume(mount, (major << 20) | minor, identity, unique_id, media_id)


def identity(*parts):
    return hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()


class TransferTrace:
    def __init__(self, fixed, removable, boot_id, host):
        if fixed.device == removable.device or fixed.filesystem_uuid == removable.filesystem_uuid:
            raise ValueError("Select two different filesystems")
        self.volumes = {fixed.device: fixed, removable.device: removable}
        self.media = removable
        self.boot_id = boot_id
        self.host = host
        self.stream_id = uuid.uuid4().hex

    def event(self, kind):
        return {
            "openedr_source": "all-os-openedr",
            "openedr_schema": 1,
            "openedr_event": kind,
            "openedr_event_id": uuid.uuid4().hex,
            "openedr_host": self.host,
            "openedr_boot_id": self.boot_id,
            "openedr_stream_id": self.stream_id,
            "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }

    def gap(self, reason):
        return {**self.event("file.copy_stream_gap"), "openedr_gap_reason": reason}

    def active(self):
        try:
            return all(unique_mount_id(volume.mount.point) == volume.unique_mount_id
                       for volume in self.volumes.values())
        except OSError:
            return False

    def parse_transfer(self, line):
        fields = line.removesuffix("\n").split("\t", 14)
        if len(fields) != 15 or fields[0] not in METHODS:
            return None
        if any(not field.isascii() or not field.isdecimal() or len(field) > 20 for field in fields[1:14]):
            return None
        stamp, start, pid, uid, source, source_ino, source_gen, source_offset, dest, dest_ino, dest_gen, dest_offset, size = (
            map(int, fields[1:14])
        )
        # The child JSON-escapes the record. A double slash cannot occur in a
        # canonical kernel pathname, including names with tabs or newlines.
        source_path, separator, dest_path = fields[14].partition(PATH_SEPARATOR)
        source_volume, dest_volume = self.volumes.get(source), self.volumes.get(dest)
        if (
            not separator or source_volume is None or dest_volume is None or source == dest
            or not source_volume.contains(source_path) or not dest_volume.contains(dest_path)
            or not all(0 < value < 2**63 for value in (stamp, start, source_ino, dest_ino, size))
            or not 0 < pid < 2**31 or uid >= 2**32
            or max(source_offset, dest_offset) + size >= 2**63
            or max(source_gen, dest_gen) >= 2**32
        ):
            return None
        record = {
            **self.event(METHODS[fields[0]]),
            "openedr_kernel_monotonic_ns": stamp,
            "openedr_pid": pid,
            "openedr_uid": uid,
            "openedr_copy_actor_id": identity(self.boot_id, pid, start),
            "openedr_copy_method": fields[0],
            "openedr_copy_direction": "to_removable" if dest_volume == self.media else "from_removable",
            "openedr_copy_bytes": size,
            "openedr_copy_removable_uuid": self.media.filesystem_uuid,
        }
        if self.media.media_id:
            record["openedr_device_id"] = self.media.media_id
        for role, volume, inode, generation, offset, path in (
            ("source", source_volume, source_ino, source_gen, source_offset, source_path),
            ("destination", dest_volume, dest_ino, dest_gen, dest_offset, dest_path),
        ):
            prefix = f"openedr_copy_{role}"
            raw_path = path.encode("utf-8", errors="surrogateescape")
            record[f"{prefix}_path"] = visible_text(raw_path)
            if record[f"{prefix}_path"] != path:
                record[f"{prefix}_path_bytes"] = raw_path.hex()
            record[f"{prefix}_id"] = identity(
                self.boot_id, volume.filesystem_uuid, volume.unique_mount_id, inode, generation,
            )
            record[f"{prefix}_offset"] = offset
        return record

    def receive(self, line):
        try:
            text = line.decode("utf-8", errors="surrogateescape") if isinstance(line, bytes) else line
            message = json.loads(text)
        except (UnicodeError, ValueError):
            return self.gap("copy_trace_invalid_record")
        if not isinstance(message, dict):
            return self.gap("copy_trace_invalid_record")
        if message.get("type") == "lost_events":
            return self.gap("copy_trace_kernel_events_lost")
        if message.get("type") == "printf" and isinstance(message.get("data"), str):
            try:
                return self.parse_transfer(message["data"])
            except UnicodeError:
                return self.gap("copy_trace_invalid_record")
        return None

    def stream(self, stream):
        poller = select.poll()
        poller.register(stream, select.POLLIN)
        pending = b""
        while self.active():
            if not poller.poll(1000):
                continue
            chunk = os.read(stream.fileno(), 64 * 1024)
            if not chunk:
                yield self.gap("copy_trace_stopped")
                return
            if not self.active():
                break
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()
            if len(pending) > MAX_LINE:
                yield self.gap("copy_trace_record_too_large")
                return
            for line in lines:
                record = self.receive(line) if len(line) <= MAX_LINE else self.gap("copy_trace_record_too_large")
                if record:
                    yield record
        yield self.gap("copy_trace_mount_changed")


class TransferLog:
    def __init__(self, trace, path=OUTPUT, clock=time.monotonic):
        self.trace = trace
        self.path = path
        self.clock = clock
        self.second = -1
        self.events = 0

    def write(self, event):
        second = int(self.clock())
        if second != self.second:
            self.second = second
            self.events = 0
        if self.events < MAX_EVENTS_PER_SECOND:
            self.events += 1
            self.append(event)
        elif event.get("openedr_gap_reason") in {"copy_trace_stopped", "copy_trace_mount_changed"}:
            self.append(event)
        elif self.events == MAX_EVENTS_PER_SECOND:
            self.events += 1
            self.append(self.trace.gap("copy_trace_rate_limit"))

    def append(self, event):
        size = len(json.dumps(event, separators=(",", ":"))) + 1
        try:
            metadata = self.path.stat(follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        if metadata is not None:
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise OSError("The transfer log must be a regular file with one link")
            if metadata.st_size + size > LOG_MAX_BYTES:
                for index in range(LOG_BACKUPS, 0, -1):
                    source = self.path if index == 1 else self.path.with_name(f"{self.path.name}.{index - 1}")
                    target = self.path.with_name(f"{self.path.name}.{index}")
                    try:
                        source.replace(target)
                    except FileNotFoundError:
                        continue
        append(event, log=self.path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixed", required=True)
    parser.add_argument("--removable", required=True)
    args = parser.parse_args()
    try:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("The removable copy tracer requires Linux amd64")
        import fcntl
        import pyudev

        context = pyudev.Context()
        mounts = mount_snapshot()
        fixed = enroll(args.fixed, mounts, context, removable=False)
        removable = enroll(args.removable, mounts, context, removable=True)
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        trace = TransferTrace(fixed, removable, boot, socket.gethostname())
        namespace = Path("/proc/self/ns/mnt").stat().st_ino
        command = ["/usr/bin/bpftrace", "-q", "-B", "line", "-f", "json", PROGRAM,
                   str(fixed.device), str(removable.device), str(namespace)]
        metadata = OUTPUT.parent.stat(follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("The removable copy tracer requires a root-owned log directory")
        flag = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        with os.fdopen(os.open(OUTPUT.with_suffix(".lock"), flag, 0o600), "r+b") as lock:
            metadata = os.fstat(lock.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077
                    or metadata.st_nlink != 1):
                raise OSError("The transfer log requires a private root-owned lock")
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            log = TransferLog(trace)
            with subprocess.Popen(command, stdout=subprocess.PIPE, env={**os.environ, "BPFTRACE_MAX_STRLEN": "256"}) as child:
                try:
                    for record in trace.stream(child.stdout):
                        log.write(record)
                finally:
                    if child.poll() is None:
                        child.terminate()
        return 1
    except (ImportError, OSError, ValueError) as error:
        print(f"all-os-openedr-removable-copies: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
