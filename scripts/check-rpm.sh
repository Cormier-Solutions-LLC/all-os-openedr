#!/bin/sh
# Run inside a disposable Enterprise Linux or Fedora container as root.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
for version in 0.2.0-nightly.20260101.gffffffffffff 0.2.0-nightly.20260101.r.9.gffffffffffff \
    0.2.0-nightly.20260101.r.10.g000000000000 0.2.0; do
    sh "$root/packaging/rpm/build.sh" "$version" "$work"
    expected=$(printf '%s' "$version" | sed 's/-/~/')
    if rpm -q all-os-openedr >/dev/null 2>&1; then
        dnf -y upgrade "$work"/all-os-openedr-"$version".*.rpm
    else
        dnf -y install "$work"/all-os-openedr-"$version".*.rpm
    fi
    test "$(rpm -q --queryformat '%{VERSION} %{ARCH}' all-os-openedr)" = "$expected noarch"
done
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
