#!/bin/sh
# Exercise the installed launcher on a disposable Debian 13 endpoint.
set -eu

if [ "$#" -ne 3 ] || [ "$(id -u)" -ne 0 ]; then
    echo "Usage: sudo sh $0 TEST_USER LOCAL_DIRECTORY MOUNTED_SMB_DIRECTORY" >&2
    exit 2
fi
. /etc/os-release
if [ "$ID" != debian ] || [ "$VERSION_ID" != 13 ] || [ "$(uname -m)" != x86_64 ]; then
    echo "Use a disposable Debian 13 amd64 endpoint" >&2
    exit 2
fi
account=$1
local_dir=$(realpath -e -- "$2")
share_dir=$(realpath -e -- "$3")
test "$(id -u -- "$account")" -ne 0
test -d "$local_dir"
test -d "$share_dir"
case "$(findmnt -n -T "$local_dir" -o FSTYPE)" in
    ext4|xfs|btrfs) ;;
    *) echo "Use a disposable local filesystem for LOCAL_DIRECTORY" >&2; exit 2 ;;
esac
case "$(findmnt -n -T "$share_dir" -o FSTYPE)" in
    cifs|smb3) ;;
    *) echo "MOUNTED_SMB_DIRECTORY must be on an SMB mount" >&2; exit 2 ;;
esac
require_offline() {
    for unit in wazuh-agent.service wazuh-manager.service; do
        state=$(systemctl show --property=ActiveState --value "$unit" 2>/dev/null || true)
        case "$state" in
            inactive|failed) ;;
            *) echo "Expected $unit to be offline, observed ${state:-unavailable}" >&2; exit 2 ;;
        esac
    done
}
require_offline
test -x /usr/bin/all-os-openedr-launch

work=$(mktemp -d /srv/openedr-offline.XXXXXXXX)
local_fixture=
share_fixture=
cleanup() {
    result=$?
    if [ "$result" -ne 0 ]; then
        for log in "$work/unknown.log" "$work/denied.log" "$work/unavailable.log" "$work/backend.log" "$work/approved.log"; do
            if [ -s "$log" ]; then cat "$log" >&2; fi
        done
    fi
    for fixture in "$local_fixture" "$share_fixture"; do
        if [ -n "$fixture" ]; then
            runuser -u "$account" -- rm -f -- "$fixture/canary"
            runuser -u "$account" -- rmdir -- "$fixture"
        fi
    done
    rm -f -- "$work/canary.c" "$work/canary" "$work/baseline" "$work/expected" \
        "$work/unknown.json" "$work/denied.json" "$work/approved.json" \
        "$work/unknown.log" "$work/denied.log" "$work/approved.log" "$work/unavailable.log" "$work/backend.log"
    rmdir -- "$work"
}
trap cleanup EXIT
chmod 0755 "$work"
local_fixture=$(runuser -u "$account" -- mktemp -d -- "$local_dir/openedr-offline.XXXXXXXX")
share_fixture=$(runuser -u "$account" -- mktemp -d -- "$share_dir/openedr-offline.XXXXXXXX")
local_file="$local_fixture/canary"
share_file="$share_fixture/canary"
printf 'original\n' > "$work/baseline"
printf 'original\napproved\n' > "$work/expected"
chmod 0644 "$work/baseline" "$work/expected"
for target in "$local_file" "$share_file"; do
    runuser -u "$account" -- sh -c 'cat > "$1"' sh "$target" < "$work/baseline"
done

cat > "$work/canary.c" <<'C'
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int append(const char *path)
{
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0)
        return 0;
    int wrote = write(fd, "approved\n", 9) == 9 && fsync(fd) == 0;
    close(fd);
    return wrote ? 1 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 4)
        return 2;
    int local = append(argv[2]);
    int share = append(argv[3]);
    if (strcmp(argv[1], "native") == 0)
        return !(local == 1 && share == 1);
    int scratch = open("/tmp/openedr-offline-result", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (scratch < 0)
        return 2;
    int finished = write(scratch, "ok\n", 3) == 3;
    close(scratch);
    return !(local == 0 && share == 0 && finished);
}
C
"${CC:-cc}" -Werror -O2 -static -o "$work/canary" "$work/canary.c"
chmod 0755 "$work/canary"
digest=$(sha256sum "$work/canary" | cut -d ' ' -f 1)
printf '{"schema":1,"verdicts":{}}\n' > "$work/unknown.json"
printf '{"schema":1,"verdicts":{"%s":"untrusted"}}\n' "$digest" > "$work/denied.json"
printf '{"schema":1,"verdicts":{"%s":"trusted"}}\n' "$digest" > "$work/approved.json"
chmod 0644 "$work/unknown.json" "$work/denied.json" "$work/approved.json"

launch() {
    decision=$1
    mode=$2
    shift 2
    catalog=$decision
    if [ "$decision" = backend ]; then catalog=unknown; fi
    systemd-run --quiet --pipe --wait --collect --uid="$account" --service-type=oneshot \
        --property=NoNewPrivileges=yes --property=TasksMax=64 --property=MemoryMax=256M "$@" \
        /usr/bin/all-os-openedr-launch --catalog "$work/$catalog.json" --timeout 15 \
        "$work/canary" "$mode" "$local_file" "$share_file" 2>"$work/$decision.log"
}
compare() {
    runuser -u "$account" -- cmp -- "$work/$1" "$local_file"
    runuser -u "$account" -- cmp -- "$work/$1" "$share_file"
}

launch unknown isolated
compare baseline
for decision in denied unavailable; do
    if launch "$decision" native; then
        echo "Launcher unexpectedly allowed $decision execution" >&2
        exit 1
    fi
    compare baseline
done
if launch backend native --property=InaccessiblePaths=/usr/bin/bwrap; then
    echo "Launcher unexpectedly allowed execution with the sandbox backend unavailable" >&2
    exit 1
fi
compare baseline
launch approved native
compare expected

python3 - "$work" <<'PY'
import json
from pathlib import Path
import sys

expected = {
    "unknown": ("isolated", "catalog_unknown"),
    "denied": ("blocked", "catalog_denied"),
    "unavailable": ("blocked", "catalog_unavailable"),
    "backend": ("blocked", "sandbox_backend_unavailable"),
    "approved": ("approved", "catalog_trusted"),
}
for fixture, decision in expected.items():
    log = Path(sys.argv[1], f"{fixture}.log")
    records = (json.loads(line) for line in log.read_text().splitlines() if line.startswith("{"))
    observed = [
        (record["openedr_containment_decision"], record["openedr_containment_reason"])
        for record in records
        if record["openedr_event"] == "executable.launch_decision"
    ]
    if observed != [decision]:
        raise SystemExit(f"Unexpected local decision for {fixture}. Expected {decision}, observed {observed}.")
    print(f"{fixture}: {decision[0]} ({decision[1]})")
PY
require_offline
echo "Offline containment preserved both protected files and allowed private scratch output."
echo "The approved control wrote to the local file and the mounted SMB share."
