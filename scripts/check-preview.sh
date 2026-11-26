#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 -B -m all_os_openedr --once --output "$work/events.jsonl"
python3 -B - "$work/events.jsonl" <<'PY'
import base64
import json
import re
import struct
import sys
from argparse import ArgumentTypeError
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree

from all_os_openedr.apparmor_policy import policy_path, profile_name, render_profile
from all_os_openedr.audit_rules import executable, login_uid, render_rules
from all_os_openedr.plugins import API_VERSION, Plugin, Registry
from all_os_openedr.proc_connector import CONNECTOR, EXEC, EXIT, FORK, NETLINK, PROC, Lifecycle, StreamGap, proc_records
from all_os_openedr.response import apply, decode_token
from all_os_openedr.samba_policy import export_directory, render_share, share_name

with TemporaryDirectory() as temporary:
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
):
    rule = audit_rules.find(f"rule[@id='{rule_id}']")
    assert rule.findtext("if_sid") == "80700"
    assert rule.findtext("field[@name='audit.type']") == "^SYSCALL$"
    assert rule.findtext("field[@name='audit.success']") == "^yes$"
    assert rule.findtext("field[@name='audit.key']") == f"^{key}$"
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
test -x "$work/package/usr/bin/all-os-openedr-audit-rules"
test -x "$work/package/usr/bin/all-os-openedr-apparmor-policy"
test -x "$work/package/usr/bin/all-os-openedr-samba-policy"
test -x "$work/package/usr/bin/all-os-openedr-response"
test -x "$work/package/usr/share/all-os-openedr/wazuh/all-os-openedr-response"
for filename in audit-localfile.xml 110110-openedr-execution_rules.xml samba-localfile.xml \
    lifecycle-localfile.xml response-localfile.xml 110100-openedr_rules.xml all-os-openedr-response \
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
