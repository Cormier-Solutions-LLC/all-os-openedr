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
    "$stage/usr/bin" "$stage/usr/share/all-os-openedr/wazuh" "$stage/usr/share/all-os-openedr/samba" \
    "$stage/usr/share/all-os-openedr/containment" "$stage/usr/share/applications"
cat > "$stage/DEBIAN/control" <<EOF
Package: all-os-openedr
Version: $package_version
Section: admin
Priority: optional
Architecture: all
Maintainer: All OS OpenEDR maintainers <all-os-openedr@users.noreply.github.com>
Depends: python3 (>= 3.10), init-system-helpers
Suggests: apparmor, auditd, bpftrace, bubblewrap, nftables, openssh-client, python3-seccomp, rsyslog, samba, samba-vfs-modules, wazuh-agent
Description: OpenEDR endpoint detection and protection preview for Linux
 The unprivileged collector writes local JSON process observations for Wazuh.
 Optional controls include IMA appraisal and managed executable containment.
EOF
install -m 0644 "$root"/all_os_openedr/*.py "$stage/usr/lib/all-os-openedr/all_os_openedr/"
install -m 0755 "$root/packaging/debian/all-os-openedr-audit-rules" \
    "$root/packaging/debian/all-os-openedr-executable-policy" \
    "$root/packaging/debian/all-os-openedr-health" \
    "$root/packaging/debian/all-os-openedr-ima" \
    "$root/packaging/debian/all-os-openedr-launch" \
    "$root/packaging/debian/all-os-openedr-run" \
    "$root/packaging/debian/all-os-openedr-apparmor-policy" \
    "$root/packaging/debian/all-os-openedr-response" \
    "$root/packaging/debian/all-os-openedr-samba-policy" "$stage/usr/bin/"
install -m 0750 "$root/integrations/wazuh/all-os-openedr-response" "$stage/usr/share/all-os-openedr/wazuh/"
install -m 0644 "$root/packaging/debian/all-os-openedr-contain-download.desktop" "$stage/usr/share/applications/"
install -m 0755 "$root/packaging/debian/all-os-openedr-ima-audit" \
    "$root/packaging/debian/all-os-openedr-containment-audit" \
    "$root/packaging/debian/all-os-openedr-launch-broker" "$stage/usr/lib/all-os-openedr/"
install -m 0644 "$root/packaging/debian/containment-decisions.bt" \
    "$stage/usr/share/all-os-openedr/containment/decisions.bt"
install -m 0644 "$root/integrations/wazuh/audit-localfile.xml" \
    "$root/integrations/wazuh/health-localfile.xml" \
    "$root/integrations/wazuh/containment-localfile.xml" \
    "$root/integrations/wazuh/containment-audit-localfile.xml" \
    "$root/integrations/wazuh/ima-dispatch.conf" \
    "$root/integrations/wazuh/ima-localfile.xml" \
    "$root/integrations/wazuh/samba-localfile.xml" \
    "$root/integrations/wazuh/lifecycle-localfile.xml" \
    "$root/integrations/wazuh/file-provenance-localfile.xml" \
    "$root/integrations/wazuh/executable-localfile.xml" \
    "$root/integrations/wazuh/policy-localfile.xml" \
    "$root/integrations/wazuh/response-localfile.xml" \
    "$root/integrations/wazuh/openedr-samba_decoders.xml" \
    "$root/integrations/wazuh/110100-openedr_rules.xml" \
    "$root/integrations/wazuh/110114-openedr-samba_rules.xml" \
    "$root/integrations/wazuh/110110-openedr-execution_rules.xml" "$stage/usr/share/all-os-openedr/wazuh/"
install -m 0644 "$root/integrations/samba/rsyslog.conf" "$stage/usr/share/all-os-openedr/samba/"
install -m 0644 "$root/packaging/debian/all-os-openedr.service" \
    "$root/packaging/debian/all-os-openedr-health.service" \
    "$root/packaging/debian/all-os-openedr-health.timer" \
    "$root/packaging/debian/all-os-openedr-containment-audit.service" \
    "$root/packaging/debian/all-os-openedr-launch.socket" \
    "$root/packaging/debian/all-os-openedr-launch@.service" \
    "$root/packaging/debian/all-os-openedr-lifecycle.service" \
    "$root/packaging/debian/all-os-openedr-file-provenance.service" \
    "$root/packaging/debian/all-os-openedr-executable.service" "$stage/usr/lib/systemd/system/"
install -m 0755 "$root/packaging/debian/prerm" "$stage/DEBIAN/prerm"
install -m 0755 "$root/packaging/debian/postinst" "$stage/DEBIAN/postinst"
install -m 0755 "$root/packaging/debian/postrm" "$stage/DEBIAN/postrm"
install -m 0644 "$root/LICENSE.md" "$stage/usr/share/doc/all-os-openedr/copyright"
install -m 0644 "$root/NOTICE.md" "$stage/usr/share/doc/all-os-openedr/NOTICE.md"
mkdir -p -- "$output"
dpkg-deb --root-owner-group --build "$stage" "$output/all-os-openedr_${version}_all.deb"
