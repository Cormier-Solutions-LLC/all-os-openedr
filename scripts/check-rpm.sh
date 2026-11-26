#!/bin/sh
# Run inside a disposable Enterprise Linux or Fedora container as root.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
sh "$root/packaging/rpm/build.sh" 0.2.0-nightly.1 "$work"
sh "$root/packaging/rpm/build.sh" 0.2.0 "$work"
dnf -y install "$work"/all-os-openedr-0.2.0-nightly.1.*.rpm
test "$(rpm -q --queryformat '%{VERSION}' all-os-openedr)" = '0.2.0~nightly.1'
dnf -y upgrade "$work"/all-os-openedr-0.2.0.*.rpm
test "$(rpm -q --queryformat '%{VERSION} %{ARCH}' all-os-openedr)" = '0.2.0 noarch'
cd /usr/lib/all-os-openedr
python=$(sed -n 's/^ExecStart=\([^ ]*\) .*/\1/p' /usr/lib/systemd/system/all-os-openedr.service)
"$python" -B -m all_os_openedr --once --output "$work/events.jsonl"
"$python" -B -c 'import json,sys; assert json.loads(open(sys.argv[1], encoding="utf-8").readline())["openedr_event"] == "process.observed"' "$work/events.jsonl"
cmp "$root/LICENSE.md" /usr/share/licenses/all-os-openedr/LICENSE.md
cmp "$root/NOTICE.md" /usr/share/licenses/all-os-openedr/NOTICE.md
if command -v systemd-analyze >/dev/null; then
    systemd-analyze verify /usr/lib/systemd/system/all-os-openedr.service
fi
dnf -y remove all-os-openedr
test ! -e /usr/lib/systemd/system/all-os-openedr.service
