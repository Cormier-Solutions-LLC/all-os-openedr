#!/bin/sh
# Run as root in the disposable Arch build container.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
chown openedr-builder "$work"
nightly=0.0.1-nightly.20260101.g000000000001
name=all-os-openedr
for version in "$nightly" 0.0.1; do
    runuser -u openedr-builder -- sh "$root/packaging/arch/build.sh" "$version" "$work"
done

test "$(vercmp 0.0.1nightly.20260101.g000000000001-1 0.0.1-1)" = -1
pacman -U --noconfirm "$work/$name-$nightly-1-any.pkg.tar.zst"
test "$(pacman -Q "$name")" = "$name 0.0.1nightly.20260101.g000000000001-1"
pacman -U --noconfirm "$work/$name-0.0.1-1-any.pkg.tar.zst"
test "$(pacman -Q "$name")" = "$name 0.0.1-1"

test "$(systemctl --root=/ is-enabled "$name.service" || true)" = disabled
systemd-analyze verify "/usr/lib/systemd/system/$name.service"
cmp "$root/LICENSE.md" "/usr/share/licenses/$name/LICENSE.md"
cmp "$root/NOTICE.md" "/usr/share/licenses/$name/NOTICE.md"
(cd "/usr/lib/$name" && python3 -B -m all_os_openedr --once --output "$work/events.jsonl")
python3 -c 'import json, sys; assert json.loads(open(sys.argv[1]).readline())["openedr_event"] == "process.observed"' "$work/events.jsonl"

systemctl --root=/ enable "$name.service"
pacman -R --noconfirm "$name"
test ! -e "/usr/lib/systemd/system/$name.service"
test ! -L "/etc/systemd/system/multi-user.target.wants/$name.service"
