#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 -B -m all_os_openedr --once --output "$work/events.jsonl"
python3 -B - "$work/events.jsonl" <<'PY'
import json
import re
import sys
from argparse import ArgumentTypeError
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from xml.etree import ElementTree

from all_os_openedr.apparmor_policy import policy_path, profile_name, render_profile
from all_os_openedr.audit_rules import executable, login_uid, render_rules
from all_os_openedr.plugins import API_VERSION, Plugin, Registry

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
dedicated_indices = ["openedr-alerts-v1-*"]
template = json.loads((integration / "openedr-index-template.json").read_text())
assert template["index_patterns"] == dedicated_indices
assert template["template"]["mappings"]["dynamic"] is False
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
test -x "$work/package/usr/bin/all-os-openedr-audit-rules"
test -x "$work/package/usr/bin/all-os-openedr-apparmor-policy"
for filename in audit-localfile.xml 110110-openedr-execution_rules.xml; do
    cmp "integrations/wazuh/$filename" "$work/package/usr/share/all-os-openedr/wazuh/$filename"
done
(cd "$work/package/usr/lib/all-os-openedr" && python3 -B -m all_os_openedr --once --output "$work/packaged.jsonl")
test -s "$work/packaged.jsonl"
set -- --set image=example.invalid/manager:verification --set opensearchUrl=https://opensearch.example.invalid:9200 \
    --set opensearchSecret=indexer --set managementSecret=manager
helm lint deploy/chart --strict "$@"
helm template openedr deploy/chart "$@" > "$work/manifests.yaml"
grep -q '^[[:space:]]*nodeTaintsPolicy: Honor$' "$work/manifests.yaml"
