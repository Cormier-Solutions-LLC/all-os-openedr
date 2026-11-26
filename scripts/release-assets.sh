#!/bin/sh
set -eu

version=${1:?usage: release-assets.sh VERSION OUTPUT_DIRECTORY}
output=${2:?usage: release-assets.sh VERSION OUTPUT_DIRECTORY}
case "$version" in
    *[!a-zA-Z0-9.+-]*|[!0-9]*) printf 'Invalid release version\n' >&2; exit 2 ;;
esac
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p -- "$output"
output=$(CDPATH='' cd -- "$output" && pwd)
cd "$root"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
sh scripts/check-preview.sh
sh packaging/debian/build.sh "$version" "$output"
git archive --format=tar.gz --prefix="all-os-openedr-${version}/" \
    --output="$output/all-os-openedr-preview-source-${version}.tar.gz" HEAD \
    LICENSE.md NOTICE.md README.md CHANGELOG.md VERSION .dockerignore all_os_openedr deploy integrations packaging scripts docs/all-os-openedr.md
cp -R deploy/chart "$work/chart"
cp LICENSE.md NOTICE.md "$work/chart/"
helm package "$work/chart" --version "$version" --app-version "$version" --destination "$output"
image="all-os-openedr-manager:$version"
docker build -f deploy/manager.Dockerfile -t "$image" .
docker save --output "$work/image.tar" "$image"
gzip -c "$work/image.tar" > "$output/all-os-openedr-manager-linux-amd64-${version}.tar.gz"
cp NOTICE.md "$output/NOTICE-${version}.md"
cp LICENSE.md "$output/LICENSE-${version}.md"
(cd "$output" && sha256sum -- ./* > "SHA256SUMS-${version}.txt.tmp")
mv -- "$output/SHA256SUMS-${version}.txt.tmp" "$output/SHA256SUMS-${version}.txt"
