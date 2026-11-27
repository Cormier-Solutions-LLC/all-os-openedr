#!/bin/sh
set -eu

version=${1:?usage: build.sh VERSION OUTPUT_DIRECTORY}
output=${2:?usage: build.sh VERSION OUTPUT_DIRECTORY}
if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-nightly\.[0-9]{8}(\.r\.[1-9][0-9]*)?\.g[0-9a-f]{12})?$'; then
    printf 'Use a numeric version or the release workflow nightly format.\n' >&2
    exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
source="$work/all-os-openedr"
mkdir -p "$source/all_os_openedr"
install -m 0644 "$root"/all_os_openedr/*.py "$source/all_os_openedr/"
install -m 0644 "$root/LICENSE.md" "$root/NOTICE.md" "$source/"
install -m 0644 "$root/packaging/debian/all-os-openedr.service" "$root/packaging/rpm/80-all-os-openedr.preset" "$source/"
install -m 0644 "$root/packaging/arch/PKGBUILD" "$root/packaging/arch/all-os-openedr.install" "$work/"
tar -czf "$work/all-os-openedr.tar.gz" -C "$work" all-os-openedr

# A prerelease with a suffix attached to its last numeric component sorts before stable.
export OPENEDR_ARCH_PKGVER="$(printf '%s' "$version" | tr -d '-')" PKGDEST="$work" PKGEXT=.pkg.tar.zst
(
    cd "$work"
    makepkg --geninteg > checksums
    cat checksums >> PKGBUILD
    makepkg --noconfirm
)
mkdir -p -- "$output"
install -m 0644 "$work/all-os-openedr-$OPENEDR_ARCH_PKGVER-1-any.pkg.tar.zst" \
    "$output/all-os-openedr-$version-1-any.pkg.tar.zst"
