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
POLICY_TARGET = re.compile(r"[0-9a-f]{32}")
POLICY_SIGNER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,63}")
MAX_POLICY_REVISION = (1 << 53) - 1


def file_version(metadata):
    return metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns


def unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate_catalog_fields")
    return fields


def parse_catalog(contents):
    if len(contents) > MAX_CATALOG_SIZE:
        raise ValueError("catalog_too_large")
    catalog = json.loads(contents, object_pairs_hook=unique_fields)
    if not isinstance(catalog, dict) or type(catalog.get("schema")) is not int:
        raise ValueError("invalid_catalog_schema")
    schema = catalog["schema"]
    if schema == 2:
        if (set(catalog) != {"schema", "target", "revision", "signer", "verdicts"}
                or not isinstance(catalog["target"], str) or not POLICY_TARGET.fullmatch(catalog["target"])
                or type(catalog["revision"]) is not int or not 1 <= catalog["revision"] <= MAX_POLICY_REVISION
                or not isinstance(catalog["signer"], str) or not POLICY_SIGNER.fullmatch(catalog["signer"])):
            raise ValueError("invalid_catalog_policy")
    elif schema != 1 or set(catalog) != {"schema", "verdicts"}:
        raise ValueError("invalid_catalog_schema")
    verdicts = catalog["verdicts"]
    if not isinstance(verdicts, dict) or any(
        not SHA256.fullmatch(key) or value not in ("trusted", "untrusted")
        for key, value in verdicts.items()
    ):
        raise ValueError("invalid_catalog_verdicts")
    return catalog


def read_catalog_record(path):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_mode & 0o022 or metadata.st_size > MAX_CATALOG_SIZE):
            raise ValueError("unsafe_catalog_file")
        contents = stream.read(MAX_CATALOG_SIZE + 1)
        if len(contents) != metadata.st_size or file_version(metadata) != file_version(os.fstat(stream.fileno())):
            raise ValueError("catalog_changed_while_reading")
    return hashlib.sha256(contents).hexdigest(), parse_catalog(contents)


def read_catalog(path):
    if path is None:
        return None, {}
    try:
        digest, catalog = read_catalog_record(path)
    except (OSError, ValueError, RecursionError):
        return None, {}
    return digest, catalog["verdicts"]


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
        self.catalog = executable_catalog
        self.catalog_version = None
        self.catalog_id, self.verdicts = None, {}

    def refresh_catalog(self):
        if self.catalog is None:
            return
        try:
            metadata = os.stat(self.catalog, follow_symlinks=False)
        except OSError:
            self.catalog_version, self.catalog_id, self.verdicts = None, None, {}
            return
        version = (metadata.st_dev, metadata.st_ino, *file_version(metadata))
        if version != self.catalog_version:
            self.catalog_id, self.verdicts = read_catalog(self.catalog)
            self.catalog_version = version

    def materialize(self, mask, pid, records):
        if mask & OVERFLOW:
            return [self.gap("fanotify_queue_overflow")]
        if not mask & OPEN_EXEC:
            return []
        event = self.base_event("executable.open")
        event.update(actor_snapshot(pid, records.get(PIDFD, -1), self.boot_id))
        event.update(inspect_descriptor(records.get(FILE_DESCRIPTOR, -1)))
        digest = event.get("openedr_executable_sha256")
        self.refresh_catalog()
        if self.catalog_id is not None:
            event["openedr_executable_catalog_sha256"] = self.catalog_id
        event["openedr_executable_verdict"] = (
            self.verdicts.get(digest, "unknown") if digest is not None and self.catalog_id else "unavailable"
        )
        return [event]
