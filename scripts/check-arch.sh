#!/bin/sh
# Run as root in the disposable Arch build container.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
chown openedr-builder "$work"
name=all-os-openedr
previous=
for version in 0.0.1-nightly.20260101.gffffffffffff 0.0.1-nightly.20260101.r.9.gffffffffffff \
    0.0.1-nightly.20260101.r.10.g000000000000 0.0.1; do
    runuser -u openedr-builder -- sh "$root/packaging/arch/build.sh" "$version" "$work"
    package="$work/$name-$version-1-any.pkg.tar.zst"
    metadata="$(pacman -Qp "$package")"
    test "$metadata" = "$name $(printf '%s' "$version" | tr -d '-')-1"
    installed=${metadata#* }
    if [ -n "$previous" ]; then
        test "$(vercmp "$previous" "$installed")" = -1
    fi
    pacman -U --noconfirm "$package"
    test "$(pacman -Q "$name")" = "$metadata"
    previous=$installed
done

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
