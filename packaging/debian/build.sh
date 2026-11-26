#!/bin/sh
set -eu

version=${1:?usage: build.sh VERSION OUTPUT_DIRECTORY}
output=${2:?usage: build.sh VERSION OUTPUT_DIRECTORY}
case "$version" in
    *[!a-zA-Z0-9.+-]*|[!0-9]*) printf 'Invalid package version\n' >&2; exit 2 ;;
esac
case "$version" in
    *-*) package_version=$(printf '%s' "$version" | sed 's/-/~/') ;;
    *) package_version=$version ;;
esac
dpkg --validate-version "$package_version"

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
install -d "$stage/DEBIAN" "$stage/usr/lib/all-os-openedr/all_os_openedr" \
    "$stage/usr/lib/systemd/system" "$stage/usr/share/doc/all-os-openedr" \
    "$stage/usr/bin" "$stage/usr/share/all-os-openedr/wazuh"
cat > "$stage/DEBIAN/control" <<EOF
Package: all-os-openedr
Version: $package_version
Section: admin
Priority: optional
Architecture: all
Maintainer: All OS OpenEDR maintainers <all-os-openedr@users.noreply.github.com>
Depends: python3 (>= 3.10), init-system-helpers
Suggests: auditd, wazuh-agent
Description: OpenEDR process telemetry preview for Linux
 The unprivileged collector writes local JSON process observations for Wazuh.
EOF
install -m 0644 "$root"/all_os_openedr/*.py "$stage/usr/lib/all-os-openedr/all_os_openedr/"
install -m 0755 "$root/packaging/debian/all-os-openedr-audit-rules" "$stage/usr/bin/"
install -m 0644 "$root/integrations/wazuh/audit-localfile.xml" \
    "$root/integrations/wazuh/110110-openedr-execution_rules.xml" "$stage/usr/share/all-os-openedr/wazuh/"
install -m 0644 "$root/packaging/debian/all-os-openedr.service" "$stage/usr/lib/systemd/system/"
install -m 0755 "$root/packaging/debian/prerm" "$stage/DEBIAN/prerm"
install -m 0755 "$root/packaging/debian/postinst" "$stage/DEBIAN/postinst"
install -m 0755 "$root/packaging/debian/postrm" "$stage/DEBIAN/postrm"
install -m 0644 "$root/LICENSE.md" "$stage/usr/share/doc/all-os-openedr/copyright"
install -m 0644 "$root/NOTICE.md" "$stage/usr/share/doc/all-os-openedr/NOTICE.md"
mkdir -p -- "$output"
dpkg-deb --root-owner-group --build "$stage" "$output/all-os-openedr_${version}_all.deb"
