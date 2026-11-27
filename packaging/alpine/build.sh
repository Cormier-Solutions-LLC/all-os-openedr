#!/bin/sh
set -eu

version=${1:?usage: build.sh VERSION OUTPUT_DIRECTORY}
output=${2:?usage: build.sh VERSION OUTPUT_DIRECTORY}
if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-nightly\.[0-9]{8}\.r\.[1-9][0-9]*\.g[0-9a-f]{12})?$'; then
    printf 'Use a numeric version or the release workflow nightly format.\n' >&2
    exit 2
fi
package_version=$version
revision=0
case "$version" in
    *-nightly.*)
        nightly=${version#*-nightly.}
        package_version=${version%%-*}_pre${nightly%%.*}
        revision=${nightly#*.r.}
        revision=${revision%%.*}
        ;;
esac

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
source="$work/all-os-openedr"
aport="$work/aports/local/all-os-openedr"
mkdir -p "$source/all_os_openedr" "$aport"
install -m 0644 "$root"/all_os_openedr/*.py "$source/all_os_openedr/"
install -m 0644 "$root/LICENSE.md" "$root/NOTICE.md" "$root/packaging/alpine/all-os-openedr.initd" "$source/"
install -m 0644 "$root/packaging/alpine/APKBUILD" "$aport/"
install -m 0755 "$root"/packaging/alpine/all-os-openedr.pre-* "$aport/"
tar -czf "$aport/all-os-openedr.tar.gz" -C "$work" all-os-openedr

export OPENEDR_APK_VERSION="$package_version" OPENEDR_APK_REVISION="$revision" REPODEST="$work/packages"
(
    cd "$aport"
    abuild checksum
    abuild
)
mkdir -p -- "$output"
install -m 0644 "$REPODEST/local/$(apk --print-arch)/all-os-openedr-$package_version-r$revision.apk" \
    "$output/all-os-openedr-$version-r$revision.apk"
