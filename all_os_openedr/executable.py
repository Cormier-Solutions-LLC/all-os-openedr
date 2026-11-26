"""Identify files opened for execution and look up local SHA-256 verdicts."""

import hashlib
import json
import os
import re
import stat
from contextlib import suppress

from .file_provenance import (
    FILE_DESCRIPTOR, OPEN_EXEC, OVERFLOW, PIDFD, FanotifyFilesystem, actor_snapshot, visible_text,
)


MAX_EXECUTABLE_SIZE = 32 * 1024 * 1024
MAX_CATALOG_SIZE = 1024 * 1024
BLOCK_SIZE = 128 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}")


def file_version(metadata):
    return metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def read_catalog(path):
    if path is None:
        return None, {}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                    or metadata.st_mode & 0o022 or metadata.st_size > MAX_CATALOG_SIZE):
                return None, {}
            contents = stream.read(MAX_CATALOG_SIZE + 1)
            if len(contents) != metadata.st_size or file_version(metadata) != file_version(os.fstat(fd)):
                return None, {}
        catalog = json.loads(contents)
    except (OSError, ValueError, RecursionError):
        return None, {}
    if (not isinstance(catalog, dict) or set(catalog) != {"schema", "verdicts"}
            or type(catalog["schema"]) is not int or catalog["schema"] != 1):
        return None, {}
    verdicts = catalog["verdicts"]
    if not isinstance(verdicts, dict) or any(
        not SHA256.fullmatch(key) or value not in ("trusted", "untrusted")
        for key, value in verdicts.items()
    ):
        return None, {}
    return hashlib.sha256(contents).hexdigest(), verdicts


def inspect_descriptor(fd, *, snapshot=None):
    status = "openedr_executable_measurement"
    if fd < 0:
        return {status: "descriptor_unavailable"}
    evidence = {status: "unreadable"}
    with suppress(OSError):
        evidence["openedr_executable_path"] = visible_text(os.readlink(os.fsencode(f"/proc/self/fd/{fd}")))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            return {**evidence, status: "not_regular"}
        evidence.update({
            "openedr_executable_size": before.st_size,
            "openedr_executable_device": f"{os.major(before.st_dev)}:{os.minor(before.st_dev)}",
            "openedr_executable_inode": str(before.st_ino),
        })
        if before.st_size > MAX_EXECUTABLE_SIZE:
            return {**evidence, status: "size_limit"}
        digest = hashlib.sha256()
        prefix = b""
        offset = 0
        while offset < before.st_size:
            block = os.pread(fd, min(before.st_size - offset, BLOCK_SIZE), offset)
            if not block:
                return {**evidence, status: "changed"}
            if len(prefix) < 4:
                prefix = (prefix + block)[:4]
            digest.update(block)
            if snapshot is not None:
                snapshot.write(block)
            offset += len(block)
        if file_version(before) != file_version(os.fstat(fd)):
            return {**evidence, status: "changed"}
    except OSError:
        return evidence
    if prefix.startswith(b"\x7fELF"):
        file_format = "elf"
    elif prefix.startswith(b"#!"):
        file_format = "script"
    else:
        file_format = "other"
    return {
        **evidence,
        status: "hashed",
        "openedr_executable_sha256": digest.hexdigest(),
        "openedr_executable_format": file_format,
    }


class ExecutableOpen(FanotifyFilesystem):
    init_flags = 0x00000083  # CLOEXEC, NONBLOCK, REPORT_PIDFD and FAN_CLASS_NOTIF.
    optional_init_flags = 0x00002000  # REPORT_FD_ERROR is unavailable on some Linux 6.12 kernels.
    event_mask = OPEN_EXEC
    retain_read_search = False
    separate_output = False
    watch_start_event = "executable.watch_started"

    def __init__(self, filesystem, output, executable_catalog=None):
        super().__init__(filesystem, output)
        self.catalog_id, self.verdicts = read_catalog(executable_catalog)

    def materialize(self, mask, pid, records):
        if mask & OVERFLOW:
            return [self.gap("fanotify_queue_overflow")]
        if not mask & OPEN_EXEC:
            return []
        event = self.base_event("executable.open")
        event.update(actor_snapshot(pid, records.get(PIDFD, -1), self.boot_id))
        event.update(inspect_descriptor(records.get(FILE_DESCRIPTOR, -1)))
        digest = event.get("openedr_executable_sha256")
        if self.catalog_id is not None:
            event["openedr_executable_catalog_sha256"] = self.catalog_id
        event["openedr_executable_verdict"] = (
            self.verdicts.get(digest, "unknown") if digest is not None and self.catalog_id else "unavailable"
        )
        return [event]
