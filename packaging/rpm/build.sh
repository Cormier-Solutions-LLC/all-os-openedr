#!/bin/sh
set -eu

version=${1:?usage: build.sh VERSION OUTPUT_DIRECTORY}
output=${2:?usage: build.sh VERSION OUTPUT_DIRECTORY}
if ! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+([.][A-Za-z0-9]+)*)?$'; then
    printf 'Use a numeric version with an optional prerelease suffix.\n' >&2
    exit 2
fi

rhel=$(rpm --eval '%{?rhel}')
fedora=$(rpm --eval '%{?fedora}')
case "$rhel:$fedora" in
    9:) target=el9; python=python3.11 ;;
    10:) target=el10; python=python3 ;;
    :[0-9]*) target="fc$fedora"; python=python3 ;;
    *) printf 'Build on Enterprise Linux 9 or 10, or Fedora.\n' >&2; exit 2 ;;
esac

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
source="$work/all-os-openedr"
mkdir -p "$work/SOURCES" "$source/all_os_openedr"
install -m 0644 "$root"/all_os_openedr/*.py "$source/all_os_openedr/"
install -m 0644 "$root/LICENSE.md" "$root/NOTICE.md" "$source/"
sed "s|^ExecStart=/usr/bin/python3 |ExecStart=/usr/bin/$python |" \
    "$root/packaging/debian/all-os-openedr.service" > "$source/all-os-openedr.service"
install -m 0644 "$root/packaging/rpm/80-all-os-openedr.preset" "$source/"
tar -czf "$work/SOURCES/all-os-openedr.tar.gz" -C "$work" all-os-openedr

rpm_version=$(printf '%s' "$version" | sed 's/-/~/')
rpmbuild -bb --define "_topdir $work" --define "openedr_version $rpm_version" \
    --define "openedr_target $target" --define "openedr_python $python" \
    "$root/packaging/rpm/all-os-openedr.spec"

mkdir -p -- "$output"
install -m 0644 "$work/RPMS/noarch/all-os-openedr-$rpm_version-1.$target.noarch.rpm" \
    "$output/all-os-openedr-$version.$target.noarch.rpm"
