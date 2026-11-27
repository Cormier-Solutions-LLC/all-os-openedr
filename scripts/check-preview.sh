#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 -B -m all_os_openedr --once --output "$work/events.jsonl"
python3 -B - "$work/events.jsonl" <<'PY'
import array
import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import socket
import struct
import tempfile
import subprocess
import sys
import threading
import uuid
from argparse import ArgumentTypeError
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, redirect_stdout
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree

from all_os_openedr.apparmor_policy import policy_path, profile_name, render_profile
from all_os_openedr.audit_rules import config_target, executable, login_uid, render_config_rules, render_rules
from all_os_openedr.containment import IMMUTABLE_SEALS, LAUNCH_FAILED, has_volume_approval, launch, namespace_status, run_backend, sandbox_identity, script_runtime
from all_os_openedr.endpoint_health import broker_health, forwarder_health, sample
from all_os_openedr.executable import ExecutableOpen, MAX_EXECUTABLE_SIZE, inspect_descriptor, parse_catalog, read_catalog
from all_os_openedr.executable_policy import policy_event, update_catalog
from all_os_openedr.file_provenance import DFID_NAME, FID, INFO_HEADER, METADATA, NEW_DFID_NAME, OLD_DFID_NAME, ON_DIRECTORY, OVERFLOW, RENAME, FileProvenance, decode_events, mounted_filesystem_uuid
from all_os_openedr.ima_audit import parse_failure as parse_ima_failure
from all_os_openedr.ima_policy import IMA_ATTRIBUTE, IMA_SHA256_PREFIX, approve as ima_approve, policy_rules, revoke as ima_revoke, select_filesystem
from all_os_openedr.launch_broker import DOCUMENT_LENGTH, DOCUMENT_LIMIT, MAX_MESSAGE, PEER, parse_policy, print_output, read_local_file, read_export, receive_snapshot, receive_message, receive_pipes, save_export, send_message, service, validate_reply
from all_os_openedr.manager import ACTIVITY_ROUTE, CONTAINMENT_ROUTE, PROCESSES_ROUTE, Index
from all_os_openedr.plugins import API_VERSION, Plugin, Registry
from all_os_openedr.proc_connector import CONNECTOR, EXEC, EXIT, FORK, NETLINK, PROC, Lifecycle, StreamGap, proc_records
from all_os_openedr.process_tree import containment_process_tree
from all_os_openedr.removable_copies import PATH_SEPARATOR, TransferLog, TransferTrace, Volume
from all_os_openedr.removable_storage import Mount, RemovableStorage
from all_os_openedr.response import apply, apply_process_response, decode_token, move_without_replacing
from all_os_openedr.sandbox_audit import ActivityBudget, parse_event as parse_sandbox_activity
from all_os_openedr.samba_policy import export_directory, render_share, share_name

with TemporaryDirectory() as temporary:
    candidate = Path(temporary) / "candidate"
    content = b"#!/bin/sh\nexit 0\n"
    digest = hashlib.sha256(content).hexdigest()
    candidate.write_bytes(content)
    with candidate.open("rb") as opened:
        candidate.unlink()
        candidate.write_bytes(b"replacement")
        snapshot = BytesIO()
        observation = inspect_descriptor(opened.fileno(), snapshot=snapshot)
        assert observation["openedr_executable_sha256"] == digest
        assert observation["openedr_executable_format"] == "script"
        assert observation["openedr_executable_path"].endswith(" (deleted)")
        assert snapshot.getvalue() == content
    with candidate.open("wb+") as opened:
        opened.truncate(MAX_EXECUTABLE_SIZE + 1)
        observation = inspect_descriptor(opened.fileno())
        assert observation["openedr_executable_measurement"] == "size_limit"
        assert "openedr_executable_sha256" not in observation
    catalog = Path(temporary) / "catalog.json"
    catalog.write_text(json.dumps({"schema": 1, "verdicts": {digest: "trusted"}}))
    if os.geteuid() == 0:
        assert read_catalog(catalog)[1] == {digest: "trusted"}
    catalog.chmod(0o666)
    assert read_catalog(catalog) == (None, {})
    assert read_catalog(None) == (None, {})

    execution_uuid = uuid.UUID("a431703b-1fb1-43c3-9344-4cfac8e9ef6c")
    assert list(policy_rules(execution_uuid)) == [
        f"appraise func=BPRM_CHECK fsuuid={execution_uuid}",
        f"appraise func=MMAP_CHECK mask=MAY_EXEC fsuuid={execution_uuid}",
    ]
    rules = list(policy_rules(execution_uuid, 999))
    assert rules[:2] == list(policy_rules(execution_uuid))
    assert rules[2:] == [
        f"dont_appraise func=FILE_CHECK mask=^MAY_READ fsuuid={execution_uuid} uid=999",
        f"appraise func=FILE_CHECK mask=^MAY_READ fsuuid={execution_uuid} uid>0",
    ]
    for invalid in (-1, 0, 4294967295):
        try:
            list(policy_rules(execution_uuid, invalid))
        except ValueError:
            pass
        else:
            raise AssertionError("IMA read policy accepted an invalid launcher UID")
    expected_user_rules = [
        f"appraise func={hook} {field}={uid} fowner>0 appraise_type=imasig"
        for uid in (1000, 1001)
        for field in ("uid", "euid")
        for hook in ("BPRM_CHECK", "CREDS_CHECK", "MMAP_CHECK mask=MAY_EXEC")
    ]
    assert list(policy_rules(execution_uuid, 999, appraise_uids=(1001, 1000, 1000))) == rules + expected_user_rules
    assert list(policy_rules(None, appraise_uids=(1001, 1000))) == expected_user_rules
    for launcher_uid, appraise_uids in ((None, ()), (999, (1000,))):
        try:
            list(policy_rules(None, launcher_uid, appraise_uids=appraise_uids))
        except ValueError:
            pass
        else:
            raise AssertionError("IMA accepted an empty policy or a volume read exception without a volume")
    for invalid in (-1, 0, 999, 4294967295, True, "1000"):
        try:
            list(policy_rules(execution_uuid, 999, appraise_uids=(1001, invalid)))
        except ValueError:
            pass
        else:
            raise AssertionError("IMA accepted an invalid appraisal UID or the containment launcher UID")
    try:
        select_filesystem("/")
    except ValueError:
        pass
    else:
        raise AssertionError("IMA accepted the root filesystem")
    configured = SimpleNamespace(execution_volume=(temporary, str(execution_uuid)))
    event = {}
    with patch("all_os_openedr.containment.select_filesystem", side_effect=OSError), \
         patch("all_os_openedr.containment.emit") as decision:
        assert launch(configured, event) == LAUNCH_FAILED
        decision.assert_called_once_with(event, "blocked", "execution_volume_unavailable")
        assert event["openedr_executable_volume_uuid"] == str(execution_uuid)
    with patch("all_os_openedr.containment.select_filesystem",
               return_value=(Path(temporary), 1, uuid.UUID(int=1))), \
         patch("all_os_openedr.containment.emit") as decision:
        assert launch(configured, event) == LAUNCH_FAILED
        decision.assert_called_once_with(event, "blocked", "execution_volume_mismatch")
    candidate.write_bytes(content)
    with candidate.open("rb") as opened:
        fd = opened.fileno()
        with patch("all_os_openedr.ima_policy.os.setxattr") as set_label:
            assert ima_approve(fd, os.fstat(fd), {digest: "trusted"}) == digest
            set_label.assert_called_once_with(fd, IMA_ATTRIBUTE, IMA_SHA256_PREFIX + bytes.fromhex(digest), os.XATTR_CREATE)
        with patch("all_os_openedr.containment.os.getxattr", return_value=IMA_SHA256_PREFIX + bytes.fromhex(digest)):
            assert has_volume_approval(fd, digest)
            assert not has_volume_approval(fd, "0" * 64)
        with patch("all_os_openedr.containment.os.getxattr", side_effect=OSError(errno.ENODATA, "absent")):
            assert not has_volume_approval(fd, digest)
        opened.seek(0)
        with patch("all_os_openedr.ima_policy.os.setxattr") as set_label:
            try:
                ima_approve(fd, os.fstat(fd), {digest: "untrusted"})
            except ValueError:
                pass
            else:
                raise AssertionError("IMA approved an untrusted hash")
            set_label.assert_not_called()
        with patch("all_os_openedr.ima_policy.os.getxattr", side_effect=OSError(errno.ENODATA, "absent")), \
             patch("all_os_openedr.ima_policy.os.removexattr") as remove_label:
            ima_revoke(fd)
            remove_label.assert_not_called()

    calls = []
    def fanotify_init(init_flags, event_flags):
        calls.append(init_flags)
        if len(calls) == 1:
            ctypes.set_errno(errno.EINVAL)
            return -1
        return 42
    collector = ExecutableOpen.__new__(ExecutableOpen)
    collector.libc = SimpleNamespace(fanotify_init=fanotify_init)
    assert collector.open_channel() == 42
    assert calls == [collector.init_flags | collector.optional_init_flags, collector.init_flags]

    protected = Path(temporary) / "approved-tool"
    protected.touch(mode=0o700)
    path = executable(str(protected))
    assert list(render_rules(path, login_uid("2300"))) == [
        f"-a always,exit -F arch={abi} -S execve,execveat -F path={path} "
        "-F auid!=2300 -F auid!=unset -F success=1 -k openedr-restricted-exec"
        for abi in ("b64", "b32")
    ]
    rules = list(render_rules(path, 2300, login_uid("1000")))
    for index, abi in enumerate(("b64", "b32")):
        restricted, session = rules[index * 2:index * 2 + 2]
        assert f"arch={abi}" in restricted and restricted.endswith("openedr-restricted-exec")
        assert f"arch={abi}" in session and "-F auid>=1000 -F auid!=unset" in session
        assert session.endswith("openedr-session-exec")
    for argument in ("4294967295", "-1", "2300 -D"):
        try:
            login_uid(argument)
        except ArgumentTypeError:
            pass
        else:
            raise AssertionError(f"Accepted invalid login UID {argument!r}")
    invalid = Path(temporary) / "tool -D"
    invalid.touch(mode=0o700)
    try:
        executable(str(invalid))
    except ArgumentTypeError:
        pass
    else:
        raise AssertionError("Accepted an executable path with a space")

    configuration = Path(temporary) / "configuration"
    configuration.mkdir()
    startup_file = Path(temporary) / "startup"
    startup_file.touch()
    target_dir, target_file = map(config_target, (str(configuration), str(startup_file)))
    assert list(render_config_rules([target_dir, target_file, target_dir])) == [
        f"-a always,exit -F arch={abi} -F {field}={target} -F perm=wa -F success=1 -k openedr-config-change"
        for field, target in (("dir", configuration), ("path", startup_file)) for abi in ("b64", "b32")
    ]
    for argument in ("/", "startup", str(invalid), str(startup_file.with_suffix(".missing")), "/dev/null"):
        try:
            config_target(argument)
        except ArgumentTypeError:
            pass
        else:
            raise AssertionError(f"Accepted an invalid configuration target {argument!r}")

    approved = policy_path("/usr/bin/true")
    data = policy_path(sys.argv[1])
    profile = render_profile(profile_name("workload"), [approved], [], [data], [])
    assert "profile all-os-openedr-workload {" in profile
    assert "signal (receive) set=(hup, int, quit, abrt, kill, term, cont) peer=unconfined," in profile
    assert "signal (send, receive) peer=all-os-openedr-workload," in profile
    assert f'  "{approved}" rix,' in profile
    assert f'  "{data}" r,' in profile
    assert "*" not in profile and "ux" not in profile
    for validator, candidate in (
        (policy_path, str(invalid)),
        (profile_name, "bad*"),
    ):
        try:
            validator(candidate)
        except ArgumentTypeError:
            pass
        else:
            raise AssertionError(f"Accepted a nonliteral profile input {candidate!r}")
    for executables, writes in (([policy_path(str(protected))], []), ([approved], [approved])):
        try:
            render_profile(profile_name("workload"), executables, [], [], writes)
        except ValueError:
            pass
        else:
            raise AssertionError("Accepted code writable outside the trusted policy")

    archive = Path(temporary) / "protected"
    archive.mkdir()
    archive_file = archive / "ledger"
    archive_file.touch()
    scratch = Path(temporary) / "scratch"
    scratch.mkdir()
    alias = Path(temporary) / "alias"
    alias.symlink_to(archive, target_is_directory=True)
    assert policy_path(str(alias), directory=True) == archive
    policy = render_profile("all-os-openedr-workload", [approved], [], [], [],
                            protected_trees=[archive], write_directories=[scratch])
    assert f'  "{archive}/**" r,' in policy
    assert f'  audit deny "{archive}/**" wl,' in policy
    assert f'  audit deny "{archive}/**" a,' in policy
    assert f'  "{scratch}/*" rw,' in policy and f'"{scratch}/**"' not in policy
    for writes, directories in (([archive_file], []), ([], [archive]), ([], [archive.parent]),
                                ([], [approved.parent])):
        try:
            render_profile("all-os-openedr-workload", [approved], [], [], writes,
                           protected_trees=[archive], write_directories=directories)
        except ValueError:
            pass
        else:
            raise AssertionError("Accepted overlapping protected or approved code paths")

    readers = SimpleNamespace(gr_gid=1001, gr_name="archive-readers")
    writers = SimpleNamespace(gr_gid=1002, gr_name="archive-writers")
    export = export_directory(str(archive))
    share = render_share(share_name("archive"), export, readers, writers)
    assert "read only = yes" in share
    assert "valid users = @archive-readers @archive-writers" in share
    assert "write list = @archive-writers" in share
    assert "server smb encrypt = required" in share
    assert "full_audit:success = none" in share
    for value in ("global", "homes", "archive\n[global]"):
        try:
            share_name(value)
        except ArgumentTypeError:
            pass
        else:
            raise AssertionError("Accepted a reserved or nonliteral share name")
    try:
        render_share("archive", export, readers, readers)
    except ValueError:
        pass
    else:
        raise AssertionError("Accepted the same group for readers and writers")

def kernel_event(kind, cpu, sequence, stamp, payload):
    event = PROC.pack(kind, cpu, stamp) + payload
    body = CONNECTOR.pack(1, 1, sequence, 0, len(event), 0) + event
    return NETLINK.pack(NETLINK.size + len(body), 3, 0, sequence, 0) + body


tracker = Lifecycle("boot", "host")


def ingest(kind, sequence, stamp, payload, cpu=0):
    record, = proc_records(kernel_event(kind, cpu, sequence, stamp, payload))
    return list(tracker.accept(record))


fork_parent, = ingest(FORK, 0xfffffffe, 100, struct.pack("=iiii", 1, 1, 200, 200))
fork_child, = ingest(FORK, 0xffffffff, 200, struct.pack("=iiii", 200, 200, 201, 201))
assert fork_child["openedr_parent_process_id"] == fork_parent["openedr_process_id"]
assert ingest(4, 0, 210, b"") == []  # Other connector events count toward continuity.
exec_child, = ingest(EXEC, 1, 250, struct.pack("=ii", 201, 201))
assert exec_child["openedr_process_id"] == fork_child["openedr_process_id"]
exit_child, = ingest(EXIT, 5, 300, struct.pack("=iiIIii", 201, 201, 9, 17, 200, 200), cpu=1)
assert exit_child["openedr_wait_status"] == 9
assert exit_child["openedr_process_id"] == fork_child["openedr_process_id"]
assert exit_child["openedr_parent_process_id"] == fork_parent["openedr_process_id"]
reused, = ingest(FORK, 2, 400, struct.pack("=iiii", 200, 200, 201, 201))
assert reused["openedr_process_id"] != fork_child["openedr_process_id"]
gap, uncorrelated = ingest(EXEC, 4, 420, struct.pack("=ii", 201, 201))
assert gap["openedr_event"] == "process.stream_gap" and gap["openedr_missing_events"] == 1
assert "openedr_process_id" not in uncorrelated
threaded, = ingest(FORK, 5, 430, struct.pack("=iiii", 1, 1, 300, 300))
thread, = ingest(FORK, 6, 440, struct.pack("=iiii", 1, 1, 301, 300))
leader_exit, = ingest(EXIT, 7, 450, struct.pack("=iiIIii", 300, 300, 0, 17, 1, 1))
worker_child, = ingest(FORK, 8, 460, struct.pack("=iiii", 301, 300, 302, 302))
worker_exit, = ingest(EXIT, 9, 470, struct.pack("=iiIIii", 301, 300, 0, 17, 1, 1))
assert thread["openedr_process_id"] == threaded["openedr_process_id"]
assert leader_exit["openedr_thread_group_leader"] and not worker_exit["openedr_thread_group_leader"]
assert worker_child["openedr_parent_process_id"] == threaded["openedr_process_id"]
assert worker_exit["openedr_process_id"] == threaded["openedr_process_id"]
assert 300 not in tracker.processes
old_exit, = ingest(EXIT, 6, 100, struct.pack("=iiIIii", 302, 302, 0, 17, 0, 0), cpu=1)
old_parent, = ingest(EXIT, 7, 110, struct.pack("=iiIIii", 400, 400, 0, 17, 302, 302), cpu=1)
assert "openedr_parent_process_id" not in old_parent
assert "openedr_process_id" not in old_exit
assert 302 in tracker.processes
try:
    list(proc_records(kernel_event(EXEC, 0, 10, 480, struct.pack("=ii", 201, 201))[:-1]))
except StreamGap:
    pass
else:
    raise AssertionError("Accepted a partial netlink frame")


class InstalledPlugin:
    def load(self):
        return Plugin("sink", API_VERSION, lambda text: text.upper())

with patch("all_os_openedr.plugins.distribution") as installed:
    installed.return_value.entry_points.select.return_value = [InstalledPlugin()]
    assert Registry({}).create("trusted-example:uppercase", "sink", text="event") == "EVENT"
    try:
        Registry({}).create("trusted-example:uppercase", "collector")
    except ValueError:
        pass
    else:
        raise AssertionError("The wrong plugin kind was accepted")

events = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
assert events and all(event["openedr_event"] == "process.observed" for event in events)
assert len(events) == len({event["openedr_event_id"] for event in events})
fixture = json.loads(Path("integrations/wazuh/process-observed.json").read_text())
assert set(events[0]) == set(fixture)
assert ElementTree.parse("integrations/wazuh/localfile.xml").findtext("log_format") == "json"
assert ElementTree.parse("integrations/wazuh/110100-openedr_rules.xml").find("rule[@id='110101']") is not None
integration = Path("integrations/wazuh")
lifecycle_feed = ElementTree.parse(integration / "lifecycle-localfile.xml")
assert lifecycle_feed.findtext("location") == "/var/log/all-os-openedr-lifecycle/events.jsonl"
assert lifecycle_feed.findtext("log_format") == "json"
lifecycle_rules = ElementTree.parse(integration / "110100-openedr_rules.xml")
assert lifecycle_rules.find("rule[@id='110102']") is not None
assert lifecycle_rules.find("rule[@id='110103']") is not None
assert lifecycle_rules.find("rule[@id='110104']") is not None
assert lifecycle_rules.find("rule[@id='110105']") is not None
assert lifecycle_rules.find("rule[@id='110106']") is not None
provenance_feed = ElementTree.parse(integration / "file-provenance-localfile.xml")
assert provenance_feed.findtext("location") == "/var/log/all-os-openedr-file-provenance/events.jsonl"
assert provenance_feed.findtext("log_format") == "json"

def file_record(kind, handle, name=None):
    payload = b"testFSID" + struct.pack("=Ii", len(handle), 1) + handle
    if name is not None:
        payload += name + b"\0"
    return INFO_HEADER.pack(kind, 0, INFO_HEADER.size + len(payload)) + payload

def file_event(mask, *records):
    packed = b"".join(records)
    return METADATA.pack(METADATA.size + len(packed), 3, 0, METADATA.size, mask, -1, 0) + packed

rename = file_event(RENAME, file_record(NEW_DFID_NAME, b"parentB", b"after"),
                    file_record(OLD_DFID_NAME, b"parentA", b"before"), file_record(FID, b"object"))
opening = file_event(0x20, file_record(DFID_NAME, b"parentA", b"before"), file_record(FID, b"object"))
decoded = list(decode_events(opening + rename + file_event(OVERFLOW)))
assert [item[0] for item in decoded] == [0x20, RENAME, OVERFLOW]
before, after = decoded[0][2], decoded[1][2]
assert before[FID].identity("boot", 1) == after[FID].identity("boot", 1)
assert before[FID].identity("boot", 1) != after[FID].identity("boot", 2)
assert after[OLD_DFID_NAME].name == b"before" and after[NEW_DFID_NAME].name == b"after"
directory = next(decode_events(file_event(ON_DIRECTORY | 0x20, file_record(DFID_NAME, b"object", b"."))))
provenance = FileProvenance("/", "/tmp/preview-file-provenance.jsonl")
provenance.device = 1
filesystem_uuid = "7e272e85-8b59-4670-94c5-44f63fbad833"
filesystem_uuid_bytes = bytes.fromhex(filesystem_uuid.replace("-", ""))

def btrfs_uuid_ioctl(fd, request, data):
    assert fd == 12
    if request == 0x80111500:
        raise OSError("generic filesystem UUID request unavailable")
    assert request == 0x8400941F
    assert len(data) == 1024
    data[16:32] = filesystem_uuid_bytes

with patch("fcntl.ioctl", side_effect=btrfs_uuid_ioctl):
    provenance.filesystem_uuid = mounted_filesystem_uuid(12)
with patch.object(provenance, "resolve_path", return_value=b"/folder"):
    observation, = provenance.materialize(*directory)
assert observation["openedr_file_object_id"] == before[FID].identity(provenance.boot_id, 1)
assert observation["openedr_file_mount_device"] == "0:1"
assert observation["openedr_file_filesystem_uuid"] == filesystem_uuid
with patch("fcntl.ioctl", side_effect=OSError("filesystem UUID unavailable")):
    assert mounted_filesystem_uuid(12) is None
assert observation["openedr_file_path"] == "/folder" and "openedr_file_parent_id" not in observation
try:
    list(decode_events(rename[:-1]))
except ValueError:
    pass
else:
    raise AssertionError("Accepted a truncated native fanotify event")

response_feed = ElementTree.parse(integration / "response-localfile.xml")
assert response_feed.findtext("location") == "/var/log/all-os-openedr-response/actions.jsonl"
assert response_feed.findtext("log_format") == "json"
policy_catalog = {"schema": 2, "target": "a" * 32, "revision": 7, "signer": "fleet-policy",
                  "verdicts": {"b" * 64: "untrusted"}}
policy_payload = json.dumps(policy_catalog).encode()
assert parse_catalog(policy_payload) == policy_catalog
for invalid in (b'{"schema":1,"schema":1,"verdicts":{}}',
                json.dumps({**policy_catalog, "revision": True}).encode(),
                json.dumps({**policy_catalog, "target": "other-endpoint"}).encode(),
                json.dumps({**policy_catalog, "verdicts": {"b" * 64: "other"}}).encode()):
    try:
        parse_catalog(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("An invalid policy catalog was accepted")
with TemporaryDirectory() as temporary:
    catalog_path = Path(temporary) / "catalog"
    catalog_path.write_bytes(b'{"schema":1,"verdicts":{}}')
    sensor = ExecutableOpen.__new__(ExecutableOpen)
    sensor.catalog, sensor.catalog_version, sensor.catalog_id, sensor.verdicts = catalog_path, None, None, {}

    def read_sample_catalog(path):
        data = path.read_bytes()
        return hashlib.sha256(data).hexdigest(), parse_catalog(data)["verdicts"]

    with patch("all_os_openedr.executable.read_catalog", side_effect=read_sample_catalog) as read, \
            patch("all_os_openedr.executable_policy.CATALOG", catalog_path):
        sensor.refresh_catalog()
        sensor.refresh_catalog()
        read.assert_called_once_with(catalog_path)
        with catalog_path.open("rb") as previous:
            update_catalog(policy_payload)
            assert parse_catalog(previous.read())["schema"] == 1
        sensor.refresh_catalog()
        assert read.call_count == 2 and sensor.verdicts == policy_catalog["verdicts"]
        assert sensor.catalog_id == hashlib.sha256(policy_payload).hexdigest()
policy_feed = ElementTree.parse(integration / "policy-localfile.xml")
assert policy_feed.findtext("location") == "/var/log/all-os-openedr-policy/changes.jsonl"
policy_receipt = policy_event("applied", policy_catalog["target"], policy_catalog, hashlib.sha256(policy_payload).hexdigest())
assert policy_receipt["openedr_policy_revision"] == 7 and policy_receipt["openedr_policy_signer"] == "fleet-policy"

usb_disk = SimpleNamespace(device_type="disk", device_number=os.makedev(8, 0), sys_path="/sys/usb1/sda", sys_name="sda",
                           properties={"ID_BUS": "usb", "ID_SERIAL": "vendor_fixture", "ID_SERIAL_SHORT": "fixture"},
                           find_parent=lambda *_: None, attributes={}, device_node="/dev/sda", device_links=[])
partition = SimpleNamespace(device_type="partition", device_number=os.makedev(8, 1), sys_path="/sys/usb1/sda/sda1",
                            sys_name="sda1", properties={"ID_FS_UUID": "fixture-volume"},
                            find_parent=lambda *_: usb_disk, action="add", device_node="/dev/sda1",
                            device_links=["/dev/disk/by-uuid/fixture-volume"])
storage = RemovableStorage()
present, = storage.add(usb_disk, "device.present")
attached, = storage.update(partition)
assert present["openedr_device_id"] == attached["openedr_device_id"]
assert attached["openedr_device_identity_scope"] == "reported_media"
assert storage.update(partition) == []
mounted_line = br"42 1 8:1 / /srv/USB\040fixtures rw - ext4 /dev/sda1 rw"
mounted, = storage.scan_mounts([mounted_line])
assert mounted["openedr_event"] == "device.mounted" and mounted["openedr_device_mountpoint"] == "/srv/USB fixtures"
assert mounted["openedr_device_number"] == "8:1" and mounted["openedr_device_filesystem_uuid"] == "fixture-volume"
assert storage.scan_mounts([mounted_line]) == []
partition.action = "remove"
removed, = storage.update(partition)
assert removed["openedr_device_attachment"] == mounted["openedr_device_attachment"]
assert storage.scan_mounts([mounted_line]) == []
unmounted, = storage.scan_mounts([])
assert unmounted["openedr_event"] == "device.unmounted" and unmounted["openedr_device_id"] == mounted["openedr_device_id"]
partition.action = "add"
reattached, = storage.update(partition)
assert reattached["openedr_device_id"] == attached["openedr_device_id"]
assert reattached["openedr_device_attachment"] != attached["openedr_device_attachment"]
btrfs_line = br"43 1 0:19 /subvolume /srv/btrfs rw - btrfs /dev/disk/by-uuid/fixture-volume rw"
btrfs_mounted, = storage.scan_mounts([btrfs_line], initial=True)
assert btrfs_mounted["openedr_event"] == "device.mount_present"
assert btrfs_mounted["openedr_device_number"] == "8:1" and btrfs_mounted["openedr_device_mount_number"] == "0:19"
assert btrfs_mounted["openedr_device_attachment"] == reattached["openedr_device_attachment"]
assert storage.scan_mounts([])[0]["openedr_event"] == "device.unmounted"
serialless = SimpleNamespace(**{**vars(usb_disk), "sys_path": "/sys/usb2/sdb", "properties": {"ID_BUS": "usb"}})
fallback, = storage.add(serialless, "device.present")
assert fallback["openedr_device_identity_scope"] == "attachment"
assert fallback["openedr_device_id"] == fallback["openedr_device_attachment"]
unrelated = SimpleNamespace(**{**vars(usb_disk), "sys_path": "/sys/pci/sdc", "properties": {"ID_BUS": "ata"}})
assert storage.add(unrelated, "device.present") == []
removable_feed = ElementTree.parse(integration / "removable-storage-localfile.xml")
assert removable_feed.findtext("location") == "/var/log/all-os-openedr-removable-storage/events.jsonl"
copy_feed = ElementTree.parse(integration / "removable-copies-localfile.xml")
assert copy_feed.findtext("location") == "/var/log/all-os-openedr-removable-copies/events.jsonl"
assert lifecycle_rules.find("rule[@id='110133']") is not None
assert lifecycle_rules.find("rule[@id='110134']") is not None
fixed_volume = Volume(Mount(51, "8:1", "/srv/fixed", "ext4", "/dev/sda1"), 8388609, "fixed-uuid", 101)
usb_volume = Volume(Mount(52, "8:2", "/srv/USB volume", "ext4", "/dev/sdb1"), 8388610, "usb-uuid", 102, "media-id")
transfer = TransferTrace(fixed_volume, usb_volume, "boot", "host")
copy_line = ("buffered\t100\t10\t1001\t1000\t8388609\t19\t8\t0\t8388610\t28\t7\t4\t64"
             f"\t/srv/fixed/input{PATH_SEPARATOR}/srv/USB volume/output\n")
record = transfer.receive(json.dumps({"type": "printf", "data": copy_line}))
assert record["openedr_event"] == "file.copy_inferred"
assert record["openedr_copy_direction"] == "to_removable" and record["openedr_copy_bytes"] == 64
assert record["openedr_copy_removable_uuid"] == "usb-uuid" and record["openedr_device_id"] == "media-id"
assert record["openedr_copy_source_id"] != record["openedr_copy_destination_id"]
assert record["openedr_copy_source_offset"] == 0 and record["openedr_copy_destination_offset"] == 4
reverse = ("copy_file_range\t110\t10\t1001\t1000\t8388610\t28\t7\t4\t8388609\t19\t8\t0\t64"
           f"\t/srv/USB volume/output{PATH_SEPARATOR}/srv/fixed/input\n")
reverse_record = transfer.parse_transfer(reverse)
assert reverse_record["openedr_event"] == "file.copy_observed"
assert reverse_record["openedr_copy_direction"] == "from_removable"
assert reverse_record["openedr_copy_actor_id"] == record["openedr_copy_actor_id"]
assert reverse_record["openedr_copy_destination_id"] == record["openedr_copy_source_id"]
assert transfer.parse_transfer(copy_line.replace("/srv/fixed/input", "/srv/fixed-bypass/input")) is None
assert transfer.parse_transfer(copy_line.replace("/srv/fixed/input", "/srv/fixed/../unrelated/input")) is None
assert transfer.parse_transfer(copy_line.replace("8388610", "8388609")) is None
unusual = copy_line.replace("input", "in\tput").replace("output", "out\nput\n")
paths = transfer.receive(json.dumps({"type": "printf", "data": unusual}).encode())
assert paths["openedr_copy_source_path"] == "/srv/fixed/in\tput"
assert paths["openedr_copy_destination_path"] == "/srv/USB volume/out\nput\n"
assert transfer.parse_transfer(copy_line.replace(PATH_SEPARATOR, "\t")) is None
assert transfer.receive(b'{"type":"lost_events","data":2}')["openedr_gap_reason"] == "copy_trace_kernel_events_lost"
with patch("all_os_openedr.removable_copies.unique_mount_id", side_effect=[101, 102]):
    assert transfer.active()
with patch("all_os_openedr.removable_copies.unique_mount_id", side_effect=[101, 103]):
    assert not transfer.active()

with patch("all_os_openedr.removable_copies.MAX_EVENTS_PER_SECOND", 2), \
        patch.object(TransferLog, "append") as capture:
    limited = TransferLog(transfer, clock=iter((1, 1, 1, 1, 1, 2)).__next__)
    for _ in range(4):
        limited.write(record)
    limited.write(transfer.gap("copy_trace_mount_changed"))
    limited.write(record)
    assert [entry.args[0].get("openedr_gap_reason") for entry in capture.call_args_list] == [
        None, None, "copy_trace_rate_limit", "copy_trace_mount_changed", None,
    ]

def append_fixture(data, *, log):
    with log.open("a", encoding="utf-8") as output:
        output.write(json.dumps(data, separators=(",", ":")) + "\n")

with tempfile.TemporaryDirectory() as directory:
    log = Path(directory) / "events.jsonl"
    with patch("all_os_openedr.removable_copies.LOG_MAX_BYTES", 40), \
            patch("all_os_openedr.removable_copies.LOG_BACKUPS", 2), \
            patch("all_os_openedr.removable_copies.append", side_effect=append_fixture):
        writer = TransferLog(transfer, path=log)
        for marker in range(12):
            writer.append({"marker": marker, "fixture": "0123456789"})
        assert [json.loads(path.read_text())["marker"] for path in sorted(log.parent.iterdir())] == [11, 10, 9]
        assert all(path.stat().st_size <= 40 for path in log.parent.iterdir())
approval = {
    "action": "release", "endpoint": "a" * 32, "agent": "001", "lease": "b" * 32,
    "alert": "1750012345.1234", "signer": "incident-operator", "issued_ms": 1750012345000, "seconds": 0,
}
encoded = base64.urlsafe_b64encode(json.dumps(approval).encode()).decode()
assert decode_token(f"v1.{encoded}.")[0] == approval
process_approval = {
    **approval, "action": "terminate", "pid": 778, "uid": 1200,
    "boot_id": "a431703b-1fb1-43c3-9344-4cfac8e9ef6c", "actor_id": "d" * 64, "unit": "workload.service",
}
payload = base64.urlsafe_b64encode(json.dumps(process_approval).encode()).decode()
assert decode_token(f"v1.{payload}.")[0] == process_approval
for fields in ({"pid": 1}, {"uid": 0}, {"boot_id": "old"}, {"actor_id": "bad"},
               {"unit": "../workload.service"}, {"seconds": 20}, {"action": "release"}):
    request = {**process_approval, **fields}
    payload = base64.urlsafe_b64encode(json.dumps(request).encode()).decode()
    try:
        decode_token(f"v1.{payload}.")
    except ValueError:
        pass
    else:
        raise AssertionError(f"Accepted an invalid process response: {fields}")
with patch("all_os_openedr.response.BOOT_ID") as boot, \
     patch("all_os_openedr.response.approval_age"), \
     patch("all_os_openedr.response.consume_approval") as consume, \
     patch("all_os_openedr.response.audit") as process_audit, \
     patch("all_os_openedr.response.verify_process_scope") as target, \
     patch("all_os_openedr.response.os.pidfd_open", return_value=23) as open_pid, \
     patch("all_os_openedr.response.os.close") as close, \
     patch("all_os_openedr.response.signal.pidfd_send_signal") as send, \
     patch("all_os_openedr.response.select.poll") as poll:
    boot.read_text.return_value = process_approval["boot_id"] + "\n"
    poll.return_value.poll.return_value = [(23, 1)]
    apply_process_response(process_approval, {"workload.service": 1200})
    open_pid.assert_called_once_with(778)
    assert target.call_count == 2
    assert send.call_args.args[0] == 23
    assert process_audit.call_args.args[0] == "terminated"
    close.assert_called_once_with(23)
    send.reset_mock()
    target.side_effect = [None, ValueError("process_identity_mismatch")]
    try:
        apply_process_response(process_approval, {"workload.service": 1200})
    except ValueError as error:
        assert str(error) == "process_identity_mismatch"
    else:
        raise AssertionError("Terminated a process after its final identity check failed")
    assert consume.call_count == 2
    send.assert_not_called()
quarantine_approval = {
    **approval, "action": "quarantine", "path": "tools/program file",
    "volume": "a431703b-1fb1-43c3-9344-4cfac8e9ef6c", "sha256": "d" * 64,
}
for request in (quarantine_approval, {**quarantine_approval, "action": "restore"}):
    payload = base64.urlsafe_b64encode(json.dumps(request).encode()).decode()
    assert decode_token(f"v1.{payload}.")[0] == request
for fields in (
    {"path": "/etc/passwd"}, {"path": "tools/../program"}, {"path": "tools//program"},
    {"path": ".openedr-quarantine/another-file"}, {"sha256": "abc"}, {"volume": "other"},
    {"seconds": 10}, {"action": "release"},
):
    request = {**quarantine_approval, **fields}
    payload = base64.urlsafe_b64encode(json.dumps(request).encode()).decode()
    try:
        decode_token(f"v1.{payload}.")
    except ValueError:
        pass
    else:
        raise AssertionError(f"Accepted an invalid file response target: {fields}")
with TemporaryDirectory() as directory, patch("all_os_openedr.response.trusted_file"):
    source = Path(directory, "source")
    destination = Path(directory, "destination")
    source.write_bytes(b"held file")
    destination.write_bytes(b"replacement")
    initial = source.stat()
    try:
        move_without_replacing(source, destination, initial)
    except ValueError as error:
        assert str(error) == "quarantine_destination_exists"
    else:
        raise AssertionError("File response overwrote a destination")
    assert source.read_bytes() == b"held file" and destination.read_bytes() == b"replacement"
    destination.unlink()
    move_without_replacing(source, destination, initial)
    assert destination.stat().st_ino == initial.st_ino and not source.exists()
with patch("all_os_openedr.response.owned_table", return_value=("c" * 32, True)), \
     patch("all_os_openedr.response.time.time_ns", return_value=approval["issued_ms"] * 1_000_000), \
     patch("all_os_openedr.response.nft") as firewall:
    try:
        apply(approval, None, None)
    except ValueError as error:
        assert str(error) == "wrong_active_lease"
    else:
        raise AssertionError("A release for another lease was accepted")
    firewall.assert_not_called()
audit_feed = ElementTree.parse(integration / "audit-localfile.xml")
assert audit_feed.findtext("location") == "/var/log/audit/audit.log"
assert audit_feed.findtext("log_format") == "audit"
audit_rules = ElementTree.parse(integration / "110110-openedr-execution_rules.xml")
for rule_id, key in (
    (110110, "openedr-restricted-exec"),
    (110111, "openedr-session-exec"),
    (110118, "openedr-config-change"),
):
    rule = audit_rules.find(f"rule[@id='{rule_id}']")
    assert rule.findtext("if_sid") == "80700"
    assert rule.findtext("field[@name='audit.type']") == "^SYSCALL$"
    assert rule.findtext("field[@name='audit.success']") == "^yes$"
    assert rule.findtext("field[@name='audit.key']") == f"^{key}$"
    if rule_id == 110118:
        assert rule.find("options") is None
        assert rule.findtext("group") == "openedr_configuration_change,"
prevention = audit_rules.find("rule[@id='110112']")
assert prevention.findtext("if_sid") == "80700"
assert prevention.findtext("group") == "openedr_execution_prevention,"
file_protection = audit_rules.find("rule[@id='110113']")
assert file_protection.findtext("if_sid") == "80700"
assert file_protection.findtext("group") == "openedr_file_protection,"
file_rule = re.compile(file_protection.findtext("match"))
record = ('type=AVC msg=audit(1795708221.152:129): apparmor="DENIED" operation="open" '
          'class="file" profile="all-os-openedr-share" name="/srv/smb/archive/ledger"')
for mask in ("w", "a", "l", "c", "d", "wc"):
    assert file_rule.search(f'{record} denied_mask="{mask}"')
assert not file_rule.search(f'{record} denied_mask="r" type=SYSCALL denied_mask="w"')
assert not file_rule.search(record.replace('class="file"', 'class="net"') + ' denied_mask="w"')
ima_failure = (b'type=INTEGRITY_DATA msg=audit(1795728256.146:111): pid=852 uid=0 auid=1000 ses=3 '
               b'subj=unconfined op=appraise_data cause=missing-hash comm="python3" name="/srv/exec/sample" '
               b'dev="vdc" ino=15 res=0 errno=0')
ima_event = parse_ima_failure(ima_failure + b'\x1dUID="root" AUID="debian"', "host", "boot")
assert ima_event["openedr_ima_cause"] == "missing-hash"
assert ima_event["openedr_ima_auid"] == 1000 and ima_event["openedr_pid"] == 852
assert ima_event["openedr_executable_path"] == "/srv/exec/sample"
assert ima_event["openedr_event_id"] == parse_ima_failure(ima_failure, "host", "boot")["openedr_event_id"]
assert parse_ima_failure(ima_failure.replace(b"res=0", b"res=1"), "host", "boot") is None
assert parse_ima_failure(ima_failure.replace(b"op=appraise_data", b"op=collect_data"), "host", "boot") is None
denied_mapping = ima_failure.replace(b"op=appraise_data cause=missing-hash", b"op=collect_data cause=failed-mprotect")
assert parse_ima_failure(denied_mapping, "host", "boot")["openedr_ima_cause"] == "failed-mprotect"
assert parse_ima_failure(denied_mapping.replace(b"res=0", b"res=1"), "host", "boot") is None
ima_rule = ElementTree.parse(integration / "110100-openedr_rules.xml").find("rule[@id='110119']")
assert re.fullmatch(ima_rule.findtext("field[@name='openedr_event']"), ima_event["openedr_event"])
status = b'{"child-pid":456,"pid-namespace":789}\n{"exit-code":42}\n'
assert namespace_status(BytesIO(status), 42) == 456
assert namespace_status(BytesIO(status), 0) is None
assert namespace_status(BytesIO(status.splitlines()[0]), 42) is None
assert namespace_status(BytesIO(b'[]\n{"exit-code":42}\n'), 42) is None
assert sandbox_identity(status) == {"openedr_containment_pid": 456, "openedr_containment_pid_namespace": 789}
assert sandbox_identity(status.splitlines()[0]) is None
assert sandbox_identity(b'{"child-pid":true}\n') is None
assert sandbox_identity(b'{"child-pid":456,"pid-namespace":true}\n') == {"openedr_containment_pid": 456}
audit_started = threading.Event()
audit_release = threading.Event()
identity = {}


def stalled_audit(created):
    identity.update(created)
    audit_started.set()
    audit_release.wait(10)


with os.fdopen(os.memfd_create("openedr-verify-status", os.MFD_CLOEXEC), "rb") as status_file:
    fd = status_file.fileno()
    child = ("import json, os, sys, time; "
             "os.write(int(sys.argv[1]), (json.dumps({'child-pid': os.getpid()}) + chr(10)).encode()); "
             "time.sleep(30)")
    with ThreadPoolExecutor(max_workers=1) as executor:
        backend = executor.submit(run_backend, [sys.executable, "-c", child, str(fd)], (fd,), fd, 2, stalled_audit)
        try:
            assert audit_started.wait(4)
            pidfd = os.pidfd_open(identity["openedr_containment_pid"])
            try:
                assert select.select([pidfd], [], [], 4)[0], "A blocked audit write extended the sandbox deadline"
            finally:
                os.close(pidfd)
        finally:
            audit_release.set()
        try:
            backend.result(5)
        except subprocess.TimeoutExpired:
            pass
        else:
            raise AssertionError("The expired backend returned normal completion")
launch_id = "a" * 32
assert CONTAINMENT_ROUTE.fullmatch("/v1/containment/" + launch_id)
assert CONTAINMENT_ROUTE.fullmatch("/v1/containment/" + launch_id + "?id=other") is None
assert PROCESSES_ROUTE.fullmatch("/v1/containment/" + launch_id + "/processes")
assert ACTIVITY_ROUTE.fullmatch("/v1/containment/" + launch_id + "/activity")
creation = {
    "openedr_source": "all-os-openedr", "openedr_event": "executable.sandbox_created",
    "openedr_containment_launch_id": launch_id, "openedr_requester_uid": 1000,
    "openedr_executable_path": "/path-that-must-stay-out-of-the-api",
}
other_launch = {**creation, "openedr_containment_launch_id": "b" * 32}
other_event = {**creation, "openedr_event": "process.exec"}
payload = {"hits": {"hits": [{"_source": {"data": event}} for event in (creation, other_launch, other_event)]}}
index = Index.__new__(Index)
index.base, index.authorization = "https://index.invalid/openedr-alerts-v1-*", "Basic fixture"
index.client = SimpleNamespace(open=lambda *_args, **_kwargs: None)
with patch.object(index.client, "open", return_value=BytesIO(json.dumps(payload).encode())) as open_search:
    matches = index.search(4, launch_id=launch_id)
    assert matches == [{key: value for key, value in creation.items() if key != "openedr_executable_path"}]
    request = json.loads(open_search.call_args.args[0].data)
    assert request["size"] == 4
    assert {"term": {"data.openedr_containment_launch_id": launch_id}} in request["query"]["bool"]["filter"]

boot = "4c6a4a9e-2e2a-484c-886d-ece33cf527b0"
stream = "b" * 32
endpoint = {"openedr_host": "endpoint", "openedr_boot_id": boot}
root_id, child_id, grandchild_id = (x * 64 for x in ("a", "c", "d"))
anchor = {**creation, **endpoint, "openedr_containment_pid": "301", "openedr_containment_monitor_pid": "300",
          "openedr_containment_fork_after_ns": "1000000.000000",
          "openedr_containment_fork_before_ns": "1100000.000000"}
root = {**endpoint, "openedr_event": "process.fork", "openedr_pid": "301", "openedr_parent_pid": "300",
        "openedr_process_id": root_id, "openedr_stream_id": stream, "openedr_kernel_monotonic_ns": "1050000.000000"}
child = {**root, "openedr_pid": "302", "openedr_process_id": child_id, "openedr_parent_process_id": root_id}
grandchild = {**child, "openedr_pid": "303", "openedr_process_id": grandchild_id,
              "openedr_parent_process_id": child_id, "openedr_executable_path": "/omit-from-tree"}
exited = {**grandchild, "openedr_event": "process.task_exit", "openedr_wait_status": 0}


def hit(data, agent="001"):
    return {"agent": {"id": agent}, "data": data}


with patch.object(index, "execute", side_effect=[
    [hit(anchor)], [hit(root)], [hit(child)], [hit(grandchild)], [], [hit(exited)],
]) as search:
    tree = containment_process_tree(index, launch_id)
    assert tree["status"] == "observed" and tree["root_process_id"] == root_id and not tree["truncated"]
    assert [node["openedr_process_id"] for node in tree["processes"]] == [root_id, child_id, grandchild_id]
    assert all("openedr_executable_path" not in row for row in (*tree["processes"], *tree["events"]))
    root_filters = search.call_args_list[1].args[0]["query"]["bool"]["filter"]
    assert {"term": {"agent.id": "001"}} in root_filters
    assert {"term": {"data.openedr_boot_id": boot}} in root_filters
    assert {"range": {"data.openedr_kernel_monotonic_ns": {"gte": 1000000, "lte": 1100000}}} in root_filters
    descendant_filters = search.call_args_list[3].args[0]["query"]["bool"]["filter"]
    assert {"terms": {"data.openedr_parent_process_id": [child_id]}} in descendant_filters
    assert {"term": {"data.openedr_stream_id": stream}} in descendant_filters
with patch.object(index, "execute", side_effect=[[hit(anchor)], [hit(root, agent="002")]]):
    assert containment_process_tree(index, launch_id)["status"] == "root_unavailable"
with patch.object(index, "execute", side_effect=[[hit(anchor)], [hit(root), hit(root)]]):
    assert containment_process_tree(index, launch_id)["status"] == "ambiguous_root"

network = parse_sandbox_activity(b"17 302 1065000 41 -1\n", "endpoint", boot, 999)
assert network["openedr_containment_activity_class"] == "network"
assert network["openedr_containment_activity_result"] == "failed"
assert network["openedr_containment_activity_errno"] == 1
assert network["openedr_containment_audit_session"] == 17
opened = parse_sandbox_activity(b"17 302 1067000 257 3\n", "endpoint", boot, 999)
assert opened["openedr_containment_activity_class"] == "file"
assert opened["openedr_containment_activity_result"] == "succeeded"
assert "openedr_containment_activity_errno" not in opened
assert parse_sandbox_activity(b"17 302 1067000 59 3\n", "endpoint", boot, 999) is None
cap = parse_sandbox_activity(b"17 302 1068000 limit 0\n", "endpoint", boot, 999)
clock = [2000000]
budget = ActivityBudget(lambda: clock[0])
recorded = [result for idx in range(320)
            if (result := budget.admit({**opened, "openedr_pid": 302 + idx % 4})) is not None]
assert len(recorded) == 129
assert recorded[-1]["openedr_containment_activity_result"] == "limit_reached"
assert "openedr_containment_activity_operation" not in recorded[-1]
assert budget.admit(cap) is None
reordered = ActivityBudget(lambda: clock[0])
assert reordered.admit(cap) == cap
assert reordered.admit(opened) == opened and reordered.admit(network) == network
assert reordered.admit(cap) is None
clock[0] += 151 * 10**9
assert budget.admit(network) is None
with patch.object(index, "execute", side_effect=[
    [hit({**anchor, "openedr_uid": "999", "openedr_containment_audit_session": "17"})],
    [hit({**network, "openedr_executable_path": "/omit-from-activity"}), hit(opened), hit(cap)],
]) as query:
    activity = index.containment_activity(launch_id)
    assert activity["status"] == "observed" and activity["truncated"] and len(activity["events"]) == 2
    assert "openedr_executable_path" not in activity["events"][0]
    filters = query.call_args.args[0]["query"]["bool"]["filter"]
    assert {"term": {"agent.id": "001"}} in filters
    assert {"term": {"data.openedr_boot_id": boot}} in filters
    assert {"term": {"data.openedr_uid": 999}} in filters
    assert {"term": {"data.openedr_containment_audit_session": 17}} in filters
for header, expected in (
    (b"#!/bin/sh\n", ("dash", ())),
    (b"#!\t/usr/bin/dash -eu\n", ("dash", ("-eu",))),
    (b"#!/usr/bin/bash -e\n", ("bash", ("-e",))),
    (b"#!/usr/bin/env sh\n", ("dash", ())),
    (b"#!/usr/bin/env -S bash -ue\n", ("bash", ("-ue",))),
    (b"#!/usr/bin/env bash -e\n", None),
    (b"#!/bin/bash -c\n", None),
    (b"#!/bin/bash\r\n", None),
    (b"#!/bin/sh\x00\n", None),
    (b"#!/usr/bin/python3\n", ("python3.13", ())),
    (b"#!/usr/bin/env python3\n", ("python3.13", ())),
    (b"#!/usr/bin/env -S python3.13 -u\n", ("python3.13", ("-u",))),
    (b"#!/usr/bin/env python3 -u\n", None),
    (b"#!/usr/bin/python3 -c\n", None),
    (b"#!/usr/bin/python3 -m\n", None),
    (b"#!/usr/local/bin/python3\n", None),
    (b"#!/usr/bin/python3.12\n", None),
    (b"#!/bin/sh" + b" " * 250 + b"\n", None),
    (b"#!/bin/sh", None),
):
    snapshot = BytesIO(header)
    snapshot.seek(0, 2)
    assert script_runtime(snapshot) == expected, header
policy = {
    "schema": 1, "filesystem": "/srv/execution", "uuid": "a431703b-1fb1-43c3-9344-4cfac8e9ef6c",
    "catalog": "/etc/verdicts.json",
    "applications": {"fixture": {"program": "tools/fixture", "uids": [1000], "arguments": ["fixed"]}},
}
empty_download = {"uids": [], "libraries": [], "python": False, "interactive": True, "arguments": ()}
assert parse_policy(policy) == (policy["filesystem"], policy["uuid"], policy["catalog"], policy["applications"], empty_download)
download_policy = {"schema": 1, "catalog": "/etc/verdicts.json", "download_uids": [1000]}
assert parse_policy(download_policy) == (None, None, "/etc/verdicts.json", {}, {**empty_download, "uids": [1000]})
library = "/usr/lib/x86_64-linux-gnu/libjq.so.1"
assert parse_policy({**download_policy, "download_libraries": [library], "download_python": True})[-1] == {
    **empty_download, "uids": [1000], "libraries": [library], "python": True,
}
for invalid in ({"download_uids": [True]}, {"download_uids": [0]}, {"filesystem": "/srv/execution"},
                {"download_python": "true"},
                {"download_libraries": [library, library]}, {"download_libraries": library},
                {"download_libraries": ["/etc/libsecret.so.1"]},
                {"download_libraries": ["/usr/lib/x86_64-linux-gnu/libc.so.6"]}):
    try:
        parse_policy({**download_policy, **invalid})
    except ValueError:
        pass
    else:
        raise AssertionError("Accepted invalid download policy")
for fields in ({"program": "../outside"}, {"program": "/bin/sh"}, {"uids": [True]},
               {"arguments": ["x" * 257]}, {"interactive": 1}, {"document": "yes"}, {"export": 1}, {"python": 1},
               {"libraries": ["/usr/lib/x86_64-linux-gnu/../x86_64-linux-gnu/libjq.so.1"]},
               {"libraries": ["libjq.so.1"]}, {"libraries": ["/usr/lib/x86_64-linux-gnu"]},
               {"libraries": [f"/usr/lib/x86_64-linux-gnu/libexample{i}.so.1" for i in range(17)]}):
    application = {**policy["applications"]["fixture"], **fields}
    try:
        parse_policy({**policy, "applications": {"fixture": application}})
    except ValueError:
        pass
    else:
        raise AssertionError(f"Invalid launch policy was accepted: {fields}")
with TemporaryDirectory() as directory:
    selected = Path(directory) / "selected document"
    selected.write_bytes(b"example\0document\xff")
    assert read_local_file(selected, DOCUMENT_LIMIT) == b"example\0document\xff"
    with selected.open("wb") as stream:
        stream.truncate(DOCUMENT_LIMIT + 1)
    for invalid in (selected, Path("/dev/zero")):
        try:
            read_local_file(invalid, DOCUMENT_LIMIT)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Accepted invalid document {invalid}")
for payload in (b"", b"example\0document\xff"):
    with ExitStack() as stack:
        peer, worker = socket.socketpair()
        stack.enter_context(peer)
        stack.enter_context(worker)
        peer.sendall(DOCUMENT_LENGTH.pack(len(payload)) + payload)
        with receive_snapshot(worker, limit=DOCUMENT_LIMIT, name="test-document", timeout=3) as snapshot:
            assert snapshot.read() == payload
            assert fcntl.fcntl(snapshot.fileno(), fcntl.F_GET_SEALS) & IMMUTABLE_SEALS == IMMUTABLE_SEALS
        for invalid in (DOCUMENT_LENGTH.pack(DOCUMENT_LIMIT + 1), DOCUMENT_LENGTH.pack(1)):
            peer.sendall(invalid)
            if invalid == DOCUMENT_LENGTH.pack(1):
                peer.shutdown(socket.SHUT_WR)
            try:
                with receive_snapshot(worker, limit=DOCUMENT_LIMIT, name="test-document", timeout=3):
                    raise AssertionError("Accepted oversized or truncated document upload")
            except ValueError:
                pass
with TemporaryDirectory() as directory:
    destination = Path(directory) / "edited document"
    payload = b"edited\0bytes\xff"
    peer, worker = socket.socketpair()
    with peer, worker:
        peer.sendall(payload)
        save_export(worker, destination, len(payload))
        assert peer.recv(1) == b"E"
        assert destination.read_bytes() == payload
        assert destination.stat().st_mode & 0o777 == 0o600
        with destination.open("rb") as stream:
            assert read_export(stream.fileno()) == payload
        alias = destination.with_name("linked document")
        alias.symlink_to(destination)
        for existing in (destination, alias):
            peer.sendall(b"changed")
            try:
                save_export(worker, existing, 7)
            except FileExistsError:
                pass
            else:
                raise AssertionError("Export overwrote an existing path")
            assert peer.recv(1) == b"E"
            assert destination.read_bytes() == payload and alias.is_symlink()
        absent = destination.with_name("missing document")
        peer.sendall(b"partial")
        peer.shutdown(socket.SHUT_WR)
        try:
            save_export(worker, absent, 8)
        except ValueError:
            pass
        else:
            raise AssertionError("Export accepted truncated data")
        assert not absent.exists()
    reply = {"decision": "isolated", "reason": "catalog_unknown", "event_id": "a" * 32, "exit_code": 0}
    validate_reply({**reply, "export_size": len(payload)}, True)
    for invalid in (reply, {**reply, "export_size": True}, {**reply, "export_size": DOCUMENT_LIMIT + 1}):
        try:
            validate_reply(invalid, True)
        except ValueError:
            pass
        else:
            raise AssertionError("Accepted an invalid export result")
with ExitStack() as stack:
    input_read, input_write = os.pipe()
    output_read, output_write = os.pipe()
    for fd in (input_read, input_write, output_read, output_write):
        stack.callback(os.close, fd)
    peer, worker = socket.socketpair()
    stack.enter_context(peer)
    stack.enter_context(worker)
    for fds in ((input_write, output_write), (input_read, input_write), (peer.fileno(), output_write),
                (input_read,), (input_read, output_write, peer.fileno()), (input_read, output_write)):
        fd_count = len(os.listdir("/proc/self/fd"))
        assert peer.sendmsg([b"I"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))]) == 1
        try:
            with receive_pipes(worker) as (received_input, received_output):
                assert fds == (input_read, output_write)
                assert not any(os.get_inheritable(fd) for fd in (received_input, received_output))
                os.write(input_write, b"input")
                assert os.read(received_input, 5) == b"input"
                os.write(received_output, b"output")
                assert os.read(output_read, 6) == b"output"
        except ValueError:
            assert fds != (input_read, output_write)
        assert len(os.listdir("/proc/self/fd")) == fd_count
with redirect_stdout(StringIO()) as rendered:
    print_output("café\t\x1b]0;title\x07\r\n")
assert rendered.getvalue() == "café\t?]0;title??\n"
peer, worker = socket.socketpair()
with peer, worker:
    send_message(peer, {"application": "fixture", "uid": 1000})
    with patch("all_os_openedr.launch_broker.emit"), patch("all_os_openedr.launch_broker.read_policy") as read:
        service(worker)
        assert receive_message(peer, 1)["reason"] == "invalid_request"
        read.assert_not_called()
peer, worker = socket.socketpair()
with peer, worker:
    send_message(peer, {"application": "fixture"})
    empty_policy = (*parse_policy(policy)[:3], {}, empty_download)
    with patch("all_os_openedr.launch_broker.read_policy", return_value=empty_policy), \
            patch("all_os_openedr.launch_broker.emit") as emit, patch("all_os_openedr.launch_broker.launch") as launch_app:
        service(worker)
        assert receive_message(peer, 1)["reason"] == "request_not_authorized"
        assert emit.call_args.args[0]["openedr_requester_uid"] == os.getuid()
        launch_app.assert_not_called()
for request in ({"download": "path"}, {"download": True, "application": "fixture"},
                {"download": True, "export": True}, {"download": True, "path": "/host/file"},
                {"download": True, "libraries": [library]}, {"application": "fixture", "libraries": [library]},
                {"download": True, "python": True}, {"application": "fixture", "python": True}):
    peer, worker = socket.socketpair()
    with peer, worker:
        send_message(peer, request)
        with patch("all_os_openedr.launch_broker.emit"), patch("all_os_openedr.launch_broker.read_policy") as read:
            service(worker)
            assert receive_message(peer, 1)["reason"] == "invalid_request"
            read.assert_not_called()
peer, worker = socket.socketpair()
with peer, worker:
    peer.sendall(b" " * MAX_MESSAGE + b"\n")
    try:
        receive_message(worker, 1)
    except ValueError:
        pass
    else:
        raise AssertionError("An oversized launch request was accepted")
health_report = {"broker": "ready", "ima": "enforcing"}
with patch("all_os_openedr.launch_broker.receive_message", return_value={"health": True}), \
        patch("all_os_openedr.launch_broker.send_message") as send, \
        patch("all_os_openedr.launch_broker.emit"), \
        patch("all_os_openedr.launch_broker.probe_broker", return_value=health_report) as probe:
    service(SimpleNamespace(getsockopt=lambda *_: PEER.pack(100, 1000, 1000)))
    assert send.call_args.args[1]["reason"] == "request_not_authorized"
    probe.assert_not_called()
    service(SimpleNamespace(getsockopt=lambda *_: PEER.pack(100, 0, 0)))
    assert send.call_args.args[1] == health_report
    probe.assert_called_once_with()
with patch("all_os_openedr.endpoint_health.socket.socket") as client, \
        patch("all_os_openedr.endpoint_health.receive_message") as receive:
    connection = client.return_value.__enter__.return_value
    connection.getsockopt.return_value = PEER.pack(1, 1000, 1000)
    assert broker_health() == ("broker_peer_untrusted", "unknown")
    receive.assert_not_called()
    connection.getsockopt.return_value = PEER.pack(1, 0, 0)
    receive.return_value = {"broker": [], "ima": "enforcing"}
    assert broker_health() == ("broker_protocol_error", "unknown")
with TemporaryDirectory() as temporary:
    state_file = Path(temporary) / "wazuh-agentd.state"
    state_file.write_bytes(b"status='connected'\n")
    with patch("all_os_openedr.endpoint_health.WAZUH_STATE", state_file), \
            patch("all_os_openedr.endpoint_health.pwd.getpwnam", return_value=SimpleNamespace(pw_uid=os.getuid())), \
            patch("all_os_openedr.endpoint_health.time.time", return_value=state_file.stat().st_mtime + 31):
        assert forwarder_health() == "state_stale"
        os.utime(state_file, (state_file.stat().st_mtime + 20,) * 2)
        assert forwarder_health() == "connected"
        state_file.chmod(0o666)
        assert forwarder_health() == "state_invalid"
with patch("all_os_openedr.endpoint_health.broker_health", return_value=("ready", "enforcing")), \
        patch("all_os_openedr.endpoint_health.forwarder_health", side_effect=("disconnected", "connected")):
    degraded = sample()
    assert degraded["openedr_health_status"] == "degraded" and degraded["openedr_health_ima"] == "enforcing"
    assert sample()["openedr_health_status"] == "ready"
containment = ElementTree.parse(integration / "containment-localfile.xml")
assert containment.findtext("location") == "/var/log/all-os-openedr-containment/launches.jsonl"
assert containment.findtext("log_format") == "json"
launch_rules = ElementTree.parse(integration / "110100-openedr_rules.xml")
assert re.fullmatch(launch_rules.findtext("rule[@id='110129']/field"), policy_receipt["openedr_event"])
assert launch_rules.findtext("rule[@id='110130']/if_sid") == "110129"
assert re.fullmatch(launch_rules.findtext("rule[@id='110131']/field"), mounted["openedr_event"])
assert re.fullmatch(launch_rules.findtext("rule[@id='110127']/field"), degraded["openedr_event"])
assert re.fullmatch(launch_rules.findtext("rule[@id='110128']/field"), degraded["openedr_health_status"])
assert launch_rules.findtext("rule[@id='110128']/if_sid") == "110127"
health_feed = ElementTree.parse(integration / "health-localfile.xml")
assert health_feed.findtext("location") == "/var/log/all-os-openedr-health/checks.jsonl"
assert health_feed.findtext("log_format") == "json"
assert launch_rules.find("rule[@id='110120']/field").attrib["name"] == "openedr_event"
assert launch_rules.findtext("rule[@id='110121']/if_sid") == "110120"
assert launch_rules.findtext("rule[@id='110122']/if_sid") == "110120"
assert re.fullmatch(launch_rules.findtext("rule[@id='110123']/field"), creation["openedr_event"])
assert re.fullmatch(launch_rules.findtext("rule[@id='110124']/field"), network["openedr_event"])
samba_feed = ElementTree.parse(integration / "samba-localfile.xml")
assert samba_feed.findtext("location") == "/var/log/samba/openedr-share-audit.log"
assert samba_feed.findtext("log_format") == "syslog"
samba_rules = ElementTree.parse(integration / "110114-openedr-samba_rules.xml")
mutation_mask = re.compile(samba_rules.findtext("rule[@id='110117']/field[@name='openedr_samba.access']"))
write_access = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
for bit in range(32):
    assert bool(mutation_mask.fullmatch(f"{1 << bit:#x}")) == bool(write_access & (1 << bit))
assert not mutation_mask.fullmatch("0x120089")
assert mutation_mask.fullmatch("0x12019f")
dedicated_indices = ["openedr-alerts-v1-*"]
template = json.loads((integration / "openedr-index-template.json").read_text())
assert template["index_patterns"] == dedicated_indices
assert template["template"]["mappings"]["dynamic"] is False
assert template["version"] >= 2
fields = template["template"]["mappings"]["properties"]["data"]["properties"]
for key, field_type in (
    ("openedr_process_id", "keyword"),
    ("openedr_parent_process_id", "keyword"),
    ("openedr_stream_id", "keyword"),
    ("openedr_kernel_monotonic_ns", "long"),
    ("openedr_wait_status", "long"),
    ("openedr_thread_group_leader", "boolean"),
    ("openedr_missing_events", "long"),
    ("openedr_response_lease", "keyword"),
    ("openedr_response_deadline_ms", "long"),
    ("openedr_response_file_sha256", "keyword"),
    ("openedr_response_volume_uuid", "keyword"),
    ("openedr_response_process_pid", "long"),
    ("openedr_response_process_uid", "long"),
    ("openedr_response_process_boot_id", "keyword"),
    ("openedr_response_process_actor_id", "keyword"),
    ("openedr_response_process_unit", "keyword"),
    ("openedr_health_status", "keyword"),
    ("openedr_health_broker", "keyword"),
    ("openedr_health_ima", "keyword"),
    ("openedr_health_forwarder", "keyword"),
    ("openedr_policy_revision", "long"),
    ("openedr_policy_signer", "keyword"),
    ("openedr_policy_result", "keyword"),
    ("openedr_policy_target", "keyword"),
    ("openedr_policy_reason", "keyword"),
    ("openedr_file_mount_device", "keyword"),
    ("openedr_file_filesystem_uuid", "keyword"),
    ("openedr_device_id", "keyword"),
    ("openedr_device_number", "keyword"),
    ("openedr_device_mount_id", "long"),
    ("openedr_device_mount_number", "keyword"),
    ("openedr_copy_direction", "keyword"),
    ("openedr_copy_bytes", "long"),
    ("openedr_copy_source_id", "keyword"),
    ("openedr_copy_destination_offset", "long"),
    ("openedr_file_actor_id", "keyword"),
    ("openedr_file_object_id", "keyword"),
    ("openedr_file_mask", "long"),
    ("openedr_file_notification_id", "keyword"),
    ("openedr_file_observed_uid", "long"),
    ("openedr_file_old_path", "keyword"),
    ("openedr_executable_sha256", "keyword"),
    ("openedr_executable_verdict", "keyword"),
    ("openedr_executable_size", "long"),
    ("openedr_executable_volume_uuid", "keyword"),
    ("openedr_ima_auid", "long"),
    ("openedr_ima_cause", "keyword"),
    ("openedr_containment_decision", "keyword"),
    ("openedr_containment_reason", "keyword"),
    ("openedr_containment_interpreter", "keyword"),
    ("openedr_containment_exit_code", "integer"),
    ("openedr_containment_pid", "long"),
    ("openedr_containment_application", "keyword"),
    ("openedr_containment_launch_id", "keyword"),
    ("openedr_containment_pid_namespace", "long"),
    ("openedr_containment_monitor_pid", "long"),
    ("openedr_containment_fork_after_ns", "long"),
    ("openedr_containment_fork_before_ns", "long"),
    ("openedr_containment_audit_session", "long"),
    ("openedr_containment_activity_class", "keyword"),
    ("openedr_containment_activity_operation", "keyword"),
    ("openedr_containment_activity_result", "keyword"),
    ("openedr_containment_activity_errno", "integer"),
    ("openedr_requester_uid", "long"),
):
    assert fields[key]["type"] == field_type
for role in ("reader", "writer"):
    policy = json.loads((integration / f"openedr-{role}-role.json").read_text())
    assert [permission["index_patterns"] for permission in policy["index_permissions"]] == [dedicated_indices]
retention = json.loads((integration / "openedr-retention-policy.json").read_text())
assert [entry["index_patterns"] for entry in retention["policy"]["ism_template"]] == [dedicated_indices]
PY
if sh packaging/macos/install.sh; then
    printf 'The macOS stub unexpectedly reported success.\n' >&2
    exit 1
else
    test "$?" -eq 2
fi
sh packaging/debian/build.sh 0.1.0-ci "$work"
package="$work/all-os-openedr_0.1.0-ci_all.deb"
test "$(dpkg-deb --field "$package" Version)" = '0.1.0~ci'
previous=
for version in 0.1.0-nightly.20260101.gffffffffffff 0.1.0-nightly.20260101.r.9.gffffffffffff \
    0.1.0-nightly.20260101.r.10.g000000000000 0.1.0; do
    sh packaging/debian/build.sh "$version" "$work"
    installed=$(dpkg-deb --field "$work/all-os-openedr_${version}_all.deb" Version)
    if [ -n "$previous" ]; then
        dpkg --compare-versions "$previous" lt "$installed"
    fi
    previous=$installed
done
dpkg-deb --extract "$package" "$work/package"
cmp NOTICE.md "$work/package/usr/share/doc/all-os-openedr/NOTICE.md"
cmp LICENSE.md "$work/package/usr/share/doc/all-os-openedr/copyright"
test -f "$work/package/usr/lib/systemd/system/all-os-openedr.service"
cmp packaging/debian/all-os-openedr-lifecycle.service \
    "$work/package/usr/lib/systemd/system/all-os-openedr-lifecycle.service"
cmp packaging/debian/all-os-openedr-file-provenance.service \
    "$work/package/usr/lib/systemd/system/all-os-openedr-file-provenance.service"
cmp packaging/debian/all-os-openedr-executable.service \
    "$work/package/usr/lib/systemd/system/all-os-openedr-executable.service"
test -x "$work/package/usr/bin/all-os-openedr-audit-rules"
test -x "$work/package/usr/bin/all-os-openedr-ima"
test -x "$work/package/usr/bin/all-os-openedr-launch"
test -x "$work/package/usr/bin/all-os-openedr-run"
test -f "$work/package/usr/share/applications/all-os-openedr-contain-download.desktop"
grep -q 'text/x-python;' "$work/package/usr/share/applications/all-os-openedr-contain-download.desktop"
test -x "$work/package/usr/lib/all-os-openedr/all-os-openedr-launch-broker"
test -x "$work/package/usr/lib/all-os-openedr/all-os-openedr-containment-audit"
cmp packaging/debian/containment-decisions.bt \
    "$work/package/usr/share/all-os-openedr/containment/decisions.bt"
cmp packaging/debian/all-os-openedr-containment-audit.service \
    "$work/package/usr/lib/systemd/system/all-os-openedr-containment-audit.service"
cmp packaging/debian/all-os-openedr-launch.socket \
    "$work/package/usr/lib/systemd/system/all-os-openedr-launch.socket"
cmp packaging/debian/all-os-openedr-launch@.service \
    "$work/package/usr/lib/systemd/system/all-os-openedr-launch@.service"
test -x "$work/package/usr/lib/all-os-openedr/all-os-openedr-ima-audit"
test -x "$work/package/usr/bin/all-os-openedr-apparmor-policy"
test -x "$work/package/usr/bin/all-os-openedr-samba-policy"
test -x "$work/package/usr/bin/all-os-openedr-response"
test -x "$work/package/usr/bin/all-os-openedr-executable-policy"
sed "s|/usr/lib/all-os-openedr|$work/package/usr/lib/all-os-openedr|g" \
    "$work/package/usr/bin/all-os-openedr-executable-policy" | sh -s -- apply --help >/dev/null
test -x "$work/package/usr/bin/all-os-openedr-health"
for unit in all-os-openedr-health.service all-os-openedr-health.timer all-os-openedr-removable-storage.service \
    all-os-openedr-removable-copies.service; do
    cmp "packaging/debian/$unit" "$work/package/usr/lib/systemd/system/$unit"
done
sed "s|/usr/lib/all-os-openedr|$work/package/usr/lib/all-os-openedr|g" \
    "$work/package/usr/bin/all-os-openedr-health" | sh -s -- --help >/dev/null
sed "s|/usr/lib/all-os-openedr|$work/package/usr/lib/all-os-openedr|g" \
    "$work/package/usr/bin/all-os-openedr-response" | sh -s -- sign --help >/dev/null
test -x "$work/package/usr/share/all-os-openedr/wazuh/all-os-openedr-response"
for filename in audit-localfile.xml 110110-openedr-execution_rules.xml samba-localfile.xml ima-dispatch.conf ima-localfile.xml containment-localfile.xml containment-audit-localfile.xml \
    lifecycle-localfile.xml file-provenance-localfile.xml executable-localfile.xml response-localfile.xml health-localfile.xml policy-localfile.xml \
    removable-copies-localfile.xml removable-storage-localfile.xml 110100-openedr_rules.xml all-os-openedr-response \
    openedr-samba_decoders.xml 110114-openedr-samba_rules.xml; do
    cmp "integrations/wazuh/$filename" "$work/package/usr/share/all-os-openedr/wazuh/$filename"
done
cmp integrations/samba/rsyslog.conf "$work/package/usr/share/all-os-openedr/samba/rsyslog.conf"
(cd "$work/package/usr/lib/all-os-openedr" && python3 -B -m all_os_openedr --once --output "$work/packaged.jsonl")
test -s "$work/packaged.jsonl"
set -- --set image=example.invalid/manager:verification --set opensearchUrl=https://opensearch.example.invalid:9200 \
    --set opensearchSecret=indexer --set managementSecret=manager
helm lint deploy/chart --strict "$@"
helm template openedr deploy/chart "$@" > "$work/manifests.yaml"
grep -q '^[[:space:]]*nodeTaintsPolicy: Honor$' "$work/manifests.yaml"
