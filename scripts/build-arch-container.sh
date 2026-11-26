#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
git -c core.autocrlf=false archive HEAD LICENSE.md NOTICE.md all_os_openedr packaging/arch \
    packaging/debian/all-os-openedr.service packaging/rpm/80-all-os-openedr.preset scripts/check-arch.sh |
    docker build -f packaging/arch/Dockerfile "$@" -
