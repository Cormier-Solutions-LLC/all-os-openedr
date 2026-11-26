#!/bin/sh
set -eu
if [ "$(uname -s)" != Darwin ]; then
    printf 'This installer entry point requires macOS.\n' >&2
    exit 2
fi
printf 'All OS OpenEDR for macOS (%s) is planned. There is no installable agent yet.\n' "$(uname -m)" >&2
exit 2
