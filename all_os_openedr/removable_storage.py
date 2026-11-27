"""Observe Linux removable block devices and their visible mounts."""

import hashlib
import os
import re
import select
import socket
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .file_provenance import visible_text


MOUNT_ESCAPE = re.compile(rb"\\(040|011|012|134)")
BLOCK_NUMBER = re.compile(rb"[0-9]+:[0-9]+")


@dataclass(frozen=True)
class Mount:
    mount_id: int
    number: str
    point: str
    filesystem: str
    source: str


@dataclass
class Attachment:
    evidence: dict
    paths: set


def mount_text(field):
    return visible_text(MOUNT_ESCAPE.sub(lambda match: bytes((int(match[1], 8),)), field))


def mounts_from(lines):
    for line in lines:
        left, separator, right = line.partition(b" - ")
        fields, filesystem = left.split(), right.split(None, 2)
        if (not separator or len(fields) < 6 or len(filesystem) != 3
                or not fields[0].isdigit() or not BLOCK_NUMBER.fullmatch(fields[2])):
            continue
        yield Mount(int(fields[0]), fields[2].decode("ascii"), mount_text(fields[4]),
                    visible_text(filesystem[0]), mount_text(filesystem[1]))


def device_paths(device):
    return {path for path in (device.device_node, *device.device_links) if path and path.startswith("/dev/")}


def property_text(device, key):
    value = device.properties.get(key, "")
    return value if value.isprintable() and len(value) <= 256 else ""


def device_evidence(device):
    kind = device.device_type
    if kind not in ("disk", "partition") or not device.device_number:
        return None
    disk = device if kind == "disk" else device.find_parent("block", "disk")
    if disk is None:
        return None
    usb = property_text(disk, "ID_BUS") == "usb" or disk.find_parent("usb", "usb_device") is not None
    if not usb and disk.attributes.get("removable") != b"1":
        return None
    number = device.device_number
    evidence = {
        "openedr_device_class": kind,
        "openedr_device_number": f"{os.major(number)}:{os.minor(number)}",
        "openedr_device_bus": "usb" if usb else property_text(disk, "ID_BUS") or "unknown",
        "openedr_device_node": device.sys_name,
    }
    wwn = property_text(disk, "ID_WWN_WITH_EXTENSION") or property_text(disk, "ID_WWN")
    serial = property_text(disk, "ID_SERIAL") if property_text(disk, "ID_SERIAL_SHORT") else ""
    if wwn or serial:
        identity = f"wwn:{wwn.lower()}" if wwn else f"serial:{evidence['openedr_device_bus']}:{serial}"
        evidence["openedr_device_id"] = hashlib.sha256(identity.encode()).hexdigest()
        evidence["openedr_device_identity_scope"] = "reported_media"
    filesystem = property_text(device, "ID_FS_UUID")
    if filesystem:
        evidence["openedr_device_filesystem_uuid"] = filesystem
    return evidence


class RemovableStorage:
    def __init__(self):
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.host = socket.gethostname()
        self.stream_id = uuid.uuid4().hex
        self.devices = {}
        self.mounts = {}

    def event(self, kind, details=None):
        return {
            "openedr_source": "all-os-openedr",
            "openedr_schema": 1,
            "openedr_event": kind,
            "openedr_event_id": uuid.uuid4().hex,
            "openedr_host": self.host,
            "openedr_boot_id": self.boot_id,
            "openedr_stream_id": self.stream_id,
            "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            **(details or {}),
        }

    def add(self, device, kind):
        if device.sys_path in self.devices:
            return []
        details = device_evidence(device)
        if details is None:
            return []
        attachment = uuid.uuid4().hex
        details["openedr_device_attachment"] = attachment
        details.setdefault("openedr_device_id", attachment)
        details.setdefault("openedr_device_identity_scope", "attachment")
        self.devices[device.sys_path] = Attachment(details, device_paths(device))
        return [self.event(kind, details)]

    def update(self, device):
        if device.action == "add":
            return self.add(device, "device.attached")
        if device.action == "remove":
            attachment = self.devices.pop(device.sys_path, None)
            return [self.event("device.removed", attachment.evidence)] if attachment is not None else []
        if device.action == "change" and device.sys_path in self.devices:
            attachment = self.devices[device.sys_path]
            attachment.paths = device_paths(device)
            filesystem = property_text(device, "ID_FS_UUID")
            if filesystem:
                attachment.evidence["openedr_device_filesystem_uuid"] = filesystem
        return []

    def mount_event(self, kind, mount, details):
        return self.event(kind, {
            **details,
            "openedr_device_mount_id": mount.mount_id,
            "openedr_device_mount_number": mount.number,
            "openedr_device_mountpoint": mount.point,
            "openedr_device_filesystem": mount.filesystem,
        })

    def scan_mounts(self, lines, *, initial=False):
        devices = {item.evidence["openedr_device_number"]: item.evidence for item in self.devices.values()}
        paths = {}
        for item in self.devices.values():
            for path in item.paths:
                paths.setdefault(path, []).append(item.evidence)
        visible = {mount.mount_id: mount for mount in mounts_from(lines)}
        events = []
        for mount_id, (mount, details) in list(self.mounts.items()):
            if visible.get(mount_id) != mount:
                events.append(self.mount_event("device.unmounted", mount, details))
                del self.mounts[mount_id]
        for mount_id, mount in visible.items():
            if mount_id in self.mounts:
                continue
            details = devices.get(mount.number)
            if details is None and mount.filesystem == "btrfs" and mount.number.startswith("0:"):
                # Btrfs can report an anonymous mount number and name its backing device as the source.
                candidates = paths.get(mount.source, ())
                if len(candidates) == 1:
                    details = candidates[0]
            if details is None:
                continue
            self.mounts[mount_id] = (mount, details.copy())
            kind = "device.mount_present" if initial else "device.mounted"
            events.append(self.mount_event(kind, mount, details))
        return events

    def stream(self):
        try:
            import pyudev
        except ImportError as error:
            raise ValueError("The removable storage collector requires python3-pyudev") from error
        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context, source="udev")
        monitor.filter_by("block")
        monitor.start()
        with open("/proc/self/mountinfo", "rb") as mountinfo:
            poller = select.poll()
            monitor_fd = monitor.fileno()
            failures = select.POLLHUP | select.POLLNVAL
            poller.register(monitor_fd, select.POLLIN)
            poller.register(mountinfo.fileno(), select.POLLPRI)
            yield [self.event("device.watch_started")]
            try:
                for device in context.list_devices(subsystem="block"):
                    if device.is_initialized:
                        events = self.add(device, "device.present")
                        if events:
                            yield events
                yield self.scan_mounts(mountinfo, initial=True)
                while True:
                    events = []
                    for descriptor, flags in poller.poll(1000):
                        if flags & failures or (descriptor == monitor_fd and flags & select.POLLERR):
                            raise OSError("Removable storage monitoring channel failed")
                        if descriptor == monitor_fd:
                            for _ in range(128):
                                device = monitor.poll(timeout=0)
                                if device is None:
                                    break
                                events.extend(self.update(device))
                    mountinfo.seek(0)
                    events.extend(self.scan_mounts(mountinfo))
                    if events:
                        yield events
            except OSError:
                yield [self.event("device.stream_gap", {"openedr_gap_reason": "device_monitor_failed"})]
                raise
