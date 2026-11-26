#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
python3 -B -m all_os_openedr --once --output "$work/events.jsonl"
python3 -B - "$work/events.jsonl" <<'PY'
import json
import sys
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree
from all_os_openedr.plugins import API_VERSION, Plugin, Registry

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
(cd "$work/package/usr/lib/all-os-openedr" && python3 -B -m all_os_openedr --once --output "$work/packaged.jsonl")
test -s "$work/packaged.jsonl"
set -- --set image=example.invalid/manager:verification --set opensearchUrl=https://opensearch.example.invalid:9200 \
    --set opensearchSecret=indexer --set managementSecret=manager
helm lint deploy/chart --strict "$@"
helm template openedr deploy/chart "$@" > "$work/manifests.yaml"
