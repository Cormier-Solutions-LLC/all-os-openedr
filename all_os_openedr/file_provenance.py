"""Collect recursive Linux file observations from an explicitly selected filesystem."""

import ctypes
import errno
import hashlib
import os
import select
import socket
import struct
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


# Linux 6.12 UAPI in include/uapi/linux/fanotify.h.
METADATA = struct.Struct("=IBBHQii")
INFO_HEADER = struct.Struct("=BBH")
HANDLE_HEADER = struct.Struct("=Ii")
PIDFD_RECORD = struct.Struct("=i")
FID, DFID_NAME, DFID, PIDFD, OLD_DFID_NAME, NEW_DFID_NAME = 1, 2, 3, 4, 10, 12
OVERFLOW = 0x4000
RENAME = 0x10000000
ON_DIRECTORY = 0x40000000
EVENTS = {
    0x00000001: "file.access",
    0x00000002: "file.modify",
    0x00000004: "file.metadata_change",
    0x00000008: "file.close_write",
    0x00000010: "file.close_readonly",
    0x00000020: "file.open",
    0x00000100: "file.create",
    0x00000200: "file.delete",
    0x00001000: "file.open_exec",
    RENAME: "file.rename",
}
EVENT_MASK = ON_DIRECTORY | sum(EVENTS)
FAN_INIT = 0x00000003 | 0x00000080 | 0x00001E00  # CLOEXEC, NONBLOCK, REPORT_PIDFD, DFID_NAME_TARGET
FAN_MARK = 0x00000001 | 0x00000100  # ADD, FILESYSTEM
PATH_OPEN_FLAGS = getattr(os, "O_PATH", 0) | getattr(os, "O_CLOEXEC", 0)


@dataclass(frozen=True)
class FileHandle:
    filesystem: bytes
    encoded: bytes
    name: bytes | None = None

    def identity(self, boot_id, device):
        scope = f"{boot_id}:{device}:".encode()
        return hashlib.sha256(scope + self.filesystem + self.encoded).hexdigest()


def decode_events(data):
    offset = 0
    while offset < len(data):
        if len(data) - offset < METADATA.size:
            raise ValueError("truncated fanotify metadata")
        size, version, _, metadata_size, mask, file_fd, pid = METADATA.unpack_from(data, offset)
        if version != 3 or not METADATA.size <= metadata_size <= size <= len(data) - offset:
            raise ValueError("invalid fanotify metadata")
        end = offset + size
        cursor = offset + metadata_size
        records = {}
        pidfd = -1
        try:
            while cursor < end:
                if end - cursor < INFO_HEADER.size:
                    raise ValueError("truncated fanotify information header")
                kind, _, length = INFO_HEADER.unpack_from(data, cursor)
                if not INFO_HEADER.size <= length <= end - cursor:
                    raise ValueError("invalid fanotify information length")
                payload = data[cursor + INFO_HEADER.size:cursor + length]
                if kind == PIDFD:
                    if len(payload) != PIDFD_RECORD.size or PIDFD in records:
                        raise ValueError("invalid fanotify process descriptor")
                    pidfd, = PIDFD_RECORD.unpack(payload)
                    records[kind] = pidfd
                elif kind in (FID, DFID, DFID_NAME, OLD_DFID_NAME, NEW_DFID_NAME):
                    if len(payload) < 8 + HANDLE_HEADER.size or kind in records:
                        raise ValueError("invalid fanotify file handle header")
                    handle_length, _ = HANDLE_HEADER.unpack_from(payload, 8)
                    handle_end = 8 + HANDLE_HEADER.size + handle_length
                    if not 0 < handle_length <= 128 or handle_end > len(payload):
                        raise ValueError("invalid fanotify file handle length")
                    name = None
                    if kind in (DFID_NAME, OLD_DFID_NAME, NEW_DFID_NAME):
                        name, terminator, _ = payload[handle_end:].partition(b"\0")
                        if not name or b"/" in name or not terminator:
                            raise ValueError("invalid fanotify directory entry")
                    records[kind] = FileHandle(payload[:8], payload[8:handle_end], name)
                cursor += length
            yield mask, pid, records
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if pidfd >= 0:
                os.close(pidfd)
        offset = end


def checked(result, operation):
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, f"{operation}: {os.strerror(error)}")
    return result


def linux_calls():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fanotify_init.argtypes = (ctypes.c_uint, ctypes.c_uint)
    libc.fanotify_mark.argtypes = (ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p)
    libc.open_by_handle_at.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int)
    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong)
    return libc


class CapHeader(ctypes.Structure):
    _fields_ = (("version", ctypes.c_uint32), ("pid", ctypes.c_int))


class CapWord(ctypes.Structure):
    _fields_ = (("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32))


def drop_setup_capabilities(libc):
    # Set no_new_privs, clear ambient capabilities, then retain only DAC_READ_SEARCH.
    checked(libc.prctl(38, 1, 0, 0, 0), "PR_SET_NO_NEW_PRIVS")
    checked(libc.prctl(47, 4, 0, 0, 0), "PR_CAP_AMBIENT_CLEAR_ALL")
    header = CapHeader(0x20080522, 0)
    words = (CapWord * 2)()
    checked(libc.capget(ctypes.byref(header), words), "capget")
    read_search = 1 << 2
    if not words[0].effective & read_search:
        raise ValueError("file provenance path resolution requires CAP_DAC_READ_SEARCH")
    words[0] = CapWord(read_search, read_search, 0)
    words[1] = CapWord(0, 0, 0)
    checked(libc.capset(ctypes.byref(header), words), "capset")


def fd_field(fd, name):
    for line in Path(f"/proc/self/fdinfo/{fd}").read_text().splitlines():
        field, _, value = line.partition(":")
        if field == name:
            return value.strip()
    return ""


def actor_snapshot(pid, pidfd, boot_id):
    if pid <= 0:
        return {"openedr_file_attribution": "unavailable"}
    actor = {"openedr_pid": pid, "openedr_file_attribution": "pid_only"}
    if pidfd < 0:
        return actor
    poller = select.poll()
    poller.register(pidfd, select.POLLIN)
    try:
        if fd_field(pidfd, "Pid") != str(pid) or poller.poll(0):
            return actor
        directory = Path(f"/proc/{pid}")
        process_stat = (directory / "stat").read_text(encoding="utf-8", errors="replace")
        opening, closing = process_stat.find("("), process_stat.rfind(")")
        fields = process_stat[closing + 1:].split()
        if opening < 0 or closing <= opening or len(fields) < 20:
            return actor
        start_ticks = int(fields[19])
        for line in (directory / "status").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Uid:"):
                uid, effective_uid, *_ = map(int, line.split()[1:])
                break
        else:
            return actor
        if poller.poll(0):
            return actor
    except (OSError, ValueError):
        return actor
    actor.update({
        "openedr_file_attribution": "pidfd_snapshot",
        "openedr_file_actor_id": hashlib.sha256(f"{boot_id}:{pid}:{start_ticks}".encode()).hexdigest(),
        "openedr_file_observed_uid": uid,
        "openedr_file_observed_euid": effective_uid,
        "openedr_process": process_stat[opening + 1:closing],
    })
    return actor


def visible_text(raw):
    return raw.decode("utf-8", errors="backslashreplace")


class FileProvenance:
    def __init__(self, filesystem, output):
        self.filesystem = Path(filesystem).resolve(strict=True)
        if not self.filesystem.is_dir() or not self.filesystem.is_mount():
            raise ValueError("select the root of an explicitly mounted filesystem")
        self.output = Path(output)
        self.host = socket.gethostname()
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.stream_id = uuid.uuid4().hex
        self.libc = linux_calls()
        self.mount_fd = -1
        self.device = 0

    def base_event(self, kind):
        return {
            "openedr_source": "all-os-openedr",
            "openedr_schema": 1,
            "openedr_event": kind,
            "openedr_event_id": uuid.uuid4().hex,
            "openedr_host": self.host,
            "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "openedr_boot_id": self.boot_id,
            "openedr_stream_id": self.stream_id,
            "openedr_file_scope": visible_text(os.fsencode(self.filesystem)),
        }

    def gap(self, reason):
        return {**self.base_event("file.stream_gap"), "openedr_gap_reason": reason}

    def resolve_path(self, handle):
        fd = self.libc.open_by_handle_at(self.mount_fd, handle.encoded, PATH_OPEN_FLAGS)
        if fd < 0:
            error = ctypes.get_errno()
            if error in (errno.ESTALE, errno.ENOENT, errno.EACCES, errno.EPERM, errno.EOPNOTSUPP):
                return None
            checked(fd, "open_by_handle_at")
        try:
            path = os.readlink(os.fsencode(f"/proc/self/fd/{fd}"))
            return path if not path.endswith(b" (deleted)") else None
        finally:
            os.close(fd)

    def directory_entry(self, handle, prefix):
        # A name of "." identifies the directory itself, rather than its parent.
        details = {}
        if handle.name != b".":
            details[f"{prefix}_parent_id"] = handle.identity(self.boot_id, self.device)
        if handle.name is None:
            return details
        details[f"{prefix}_name"] = visible_text(handle.name)
        if details[f"{prefix}_name"].encode() != handle.name:
            details[f"{prefix}_name_bytes"] = handle.name.hex()
        parent = self.resolve_path(handle)
        if parent is not None:
            path = parent if handle.name == b"." else os.path.join(parent, handle.name)
            details[f"{prefix}_path"] = visible_text(path)
            details[f"{prefix}_path_source"] = (
                "observed_directory_handle" if handle.name == b"." else "reported_name_resolved_parent"
            )
        return details

    def materialize(self, mask, pid, records):
        if mask & OVERFLOW:
            return [self.gap("fanotify_queue_overflow")]
        if pid == os.getpid():
            return []
        actor = actor_snapshot(pid, records.get(PIDFD, -1), self.boot_id)
        details = {
            **actor,
            "openedr_file_directory": bool(mask & ON_DIRECTORY),
            "openedr_file_mask": mask,
        }
        target = records.get(FID)
        if target is not None:
            details["openedr_file_object_id"] = target.identity(self.boot_id, self.device)
            details["openedr_file_filesystem_id"] = target.filesystem.hex()
        parent = records.get(NEW_DFID_NAME) or records.get(DFID_NAME) or records.get(DFID)
        if parent is not None:
            details.update(self.directory_entry(parent, "openedr_file"))
        old_parent = records.get(OLD_DFID_NAME)
        if old_parent is not None:
            details.update(self.directory_entry(old_parent, "openedr_file_old"))
        # A one-sided rename can identify its old name without a new location.
        if target is not None and not mask & RENAME and "openedr_file_path" not in details:
            path = self.resolve_path(target)
            if path is not None:
                details["openedr_file_path"] = visible_text(path)
                details["openedr_file_path_source"] = "observed_target_handle"
        return [{**self.base_event(kind), **details} for bit, kind in EVENTS.items() if mask & bit]

    def same_mount(self, expected):
        try:
            fd = os.open(self.filesystem, PATH_OPEN_FLAGS | os.O_DIRECTORY)
        except OSError:
            return False
        try:
            return fd_field(fd, "mnt_id") == expected and os.fstat(fd).st_dev == self.device
        finally:
            os.close(fd)

    def writes_to_watched_filesystem(self):
        target = self.output.resolve()
        try:
            return target.stat().st_dev == self.device
        except FileNotFoundError:
            return target.parent.stat().st_dev == self.device

    def stream(self):
        # Linux 6.12 open_by_handle_at uses fdget(), which rejects an O_PATH mount descriptor.
        self.mount_fd = os.open(self.filesystem, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        try:
            self.device = os.fstat(self.mount_fd).st_dev
            if self.writes_to_watched_filesystem():
                raise ValueError("file provenance logs require a different filesystem from the watch target")
            mount_id = fd_field(self.mount_fd, "mnt_id")
            if not mount_id:
                raise ValueError("the selected filesystem has no visible mount ID")
            fd = checked(self.libc.fanotify_init(FAN_INIT, os.O_RDONLY | os.O_CLOEXEC), "fanotify_init")
            try:
                checked(self.libc.fanotify_mark(fd, FAN_MARK, EVENT_MASK, self.mount_fd, b"."), "fanotify_mark")
                drop_setup_capabilities(self.libc)
                poller = select.poll()
                poller.register(fd, select.POLLIN)
                next_check = time.monotonic()
                yield [self.base_event("file.watch_started")]
                while True:
                    if time.monotonic() >= next_check:
                        next_check = time.monotonic() + 2
                        if not self.same_mount(mount_id):
                            yield [self.gap("file_watch_target_changed")]
                            raise ValueError("the watched mount changed")
                        if self.writes_to_watched_filesystem():
                            raise ValueError("file provenance logs moved onto the watched filesystem")
                    notifications = poller.poll(500)
                    if not notifications:
                        continue
                    if notifications[0][1] & (select.POLLERR | select.POLLHUP | select.POLLNVAL):
                        yield [self.gap("fanotify_channel_error")]
                        raise ValueError("the fanotify channel failed")
                    batch = []
                    try:
                        # PIDFDs are installed during read, so consume the entire batch before yielding.
                        data = os.read(fd, 64 * 1024)
                        if not data:
                            raise ValueError("fanotify returned an empty batch")
                        for mask, pid, records in decode_events(data):
                            batch.extend(self.materialize(mask, pid, records))
                    except BlockingIOError:
                        continue
                    except (OSError, ValueError):
                        yield [*batch, self.gap("fanotify_batch_error")]
                        raise
                    if batch:
                        yield batch
            finally:
                os.close(fd)
        finally:
            os.close(self.mount_fd)
            self.mount_fd = -1
