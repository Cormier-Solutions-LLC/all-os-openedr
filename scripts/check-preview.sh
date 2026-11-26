#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 -B -m all_os_openedr --once --output "$work/events.jsonl"
python3 -B - "$work/events.jsonl" <<'PY'
import base64
import ctypes
import errno
import hashlib
import json
import os
import re
import struct
import sys
import uuid
from argparse import ArgumentTypeError
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree

from all_os_openedr.apparmor_policy import policy_path, profile_name, render_profile
from all_os_openedr.audit_rules import config_target, executable, login_uid, render_config_rules, render_rules
from all_os_openedr.containment import namespace_status
from all_os_openedr.executable import ExecutableOpen, MAX_EXECUTABLE_SIZE, inspect_descriptor, read_catalog
from all_os_openedr.file_provenance import DFID_NAME, FID, INFO_HEADER, METADATA, NEW_DFID_NAME, OLD_DFID_NAME, ON_DIRECTORY, OVERFLOW, RENAME, FileProvenance, decode_events
from all_os_openedr.ima_audit import parse_failure as parse_ima_failure
from all_os_openedr.ima_policy import IMA_ATTRIBUTE, IMA_SHA256_PREFIX, approve as ima_approve, policy_rules, revoke as ima_revoke, select_filesystem
from all_os_openedr.plugins import API_VERSION, Plugin, Registry
from all_os_openedr.proc_connector import CONNECTOR, EXEC, EXIT, FORK, NETLINK, PROC, Lifecycle, StreamGap, proc_records
from all_os_openedr.response import apply, decode_token
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
    try:
        select_filesystem("/")
    except ValueError:
        pass
    else:
        raise AssertionError("IMA accepted the root filesystem")
    candidate.write_bytes(content)
    with candidate.open("rb") as opened:
        fd = opened.fileno()
        with patch("all_os_openedr.ima_policy.os.setxattr") as set_label:
            assert ima_approve(fd, os.fstat(fd), {digest: "trusted"}) == digest
            set_label.assert_called_once_with(fd, IMA_ATTRIBUTE, IMA_SHA256_PREFIX + bytes.fromhex(digest), os.XATTR_CREATE)
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
with patch.object(provenance, "resolve_path", return_value=b"/folder"):
    observation, = provenance.materialize(*directory)
assert observation["openedr_file_object_id"] == before[FID].identity(provenance.boot_id, 1)
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
approval = {
    "action": "release", "endpoint": "a" * 32, "agent": "001", "lease": "b" * 32,
    "alert": "1750012345.1234", "signer": "incident-operator", "issued_ms": 1750012345000, "seconds": 0,
}
encoded = base64.urlsafe_b64encode(json.dumps(approval).encode()).decode()
assert decode_token(f"v1.{encoded}.")[0] == approval
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
ima_rule = ElementTree.parse(integration / "110100-openedr_rules.xml").find("rule[@id='110119']")
assert re.fullmatch(ima_rule.findtext("field[@name='openedr_event']"), ima_event["openedr_event"])
status = b'{"child-pid":456,"pid-namespace":789}\n{"exit-code":42}\n'
assert namespace_status(BytesIO(status), 42) == 456
assert namespace_status(BytesIO(status), 0) is None
assert namespace_status(BytesIO(status.splitlines()[0]), 42) is None
assert namespace_status(BytesIO(b'[]\n{"exit-code":42}\n'), 42) is None
containment = ElementTree.parse(integration / "containment-localfile.xml")
assert containment.findtext("location") == "/var/log/all-os-openedr-containment/launches.jsonl"
assert containment.findtext("log_format") == "json"
launch_rules = ElementTree.parse(integration / "110100-openedr_rules.xml")
assert launch_rules.find("rule[@id='110120']/field").attrib["name"] == "openedr_event"
assert launch_rules.findtext("rule[@id='110121']/if_sid") == "110120"
assert launch_rules.findtext("rule[@id='110122']/if_sid") == "110120"
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
    ("openedr_file_actor_id", "keyword"),
    ("openedr_file_object_id", "keyword"),
    ("openedr_file_mask", "long"),
    ("openedr_file_notification_id", "keyword"),
    ("openedr_file_observed_uid", "long"),
    ("openedr_file_old_path", "keyword"),
    ("openedr_executable_sha256", "keyword"),
    ("openedr_executable_verdict", "keyword"),
    ("openedr_executable_size", "long"),
    ("openedr_ima_auid", "long"),
    ("openedr_ima_cause", "keyword"),
    ("openedr_containment_decision", "keyword"),
    ("openedr_containment_reason", "keyword"),
    ("openedr_containment_exit_code", "integer"),
    ("openedr_containment_pid", "long"),
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
test -x "$work/package/usr/lib/all-os-openedr/all-os-openedr-ima-audit"
test -x "$work/package/usr/bin/all-os-openedr-apparmor-policy"
test -x "$work/package/usr/bin/all-os-openedr-samba-policy"
test -x "$work/package/usr/bin/all-os-openedr-response"
test -x "$work/package/usr/share/all-os-openedr/wazuh/all-os-openedr-response"
for filename in audit-localfile.xml 110110-openedr-execution_rules.xml samba-localfile.xml ima-dispatch.conf ima-localfile.xml containment-localfile.xml \
    lifecycle-localfile.xml file-provenance-localfile.xml executable-localfile.xml response-localfile.xml \
    110100-openedr_rules.xml all-os-openedr-response \
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
