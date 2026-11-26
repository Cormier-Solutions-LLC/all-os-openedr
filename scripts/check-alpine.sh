#!/bin/sh
# Run as root in a disposable Alpine container with the source mounted read-only.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
apk add --no-cache alpine-sdk openrc python3
adduser -D openedr-builder
su - openedr-builder -c 'abuild-keygen -anq'
install -m 0644 /home/openedr-builder/.abuild/*.rsa.pub /etc/apk/keys/

for version in 0.0.1 0.0.2; do
    su - openedr-builder -c "sh '$root/packaging/alpine/build.sh' $version /home/openedr-builder/packages"
done
packages=/home/openedr-builder/packages
mkdir -p /run/openrc
touch /run/openrc/softlevel

service=all-os-openedr
log=/var/log/$service/events.jsonl
# The runtime dependencies are already installed. Exercise the signed local package offline.
apk --no-network add "$packages/$service-0.0.1-r0.apk"
apk --no-network info -e "$service"
test ! -e "/etc/runlevels/default/$service"
test ! -e "/run/$service.pid"
cmp "$root/LICENSE.md" "/usr/share/licenses/$service/LICENSE.md"
cmp "$root/NOTICE.md" "/usr/share/licenses/$service/NOTICE.md"

rc-service "$service" start
for attempt in 1 2 3 4 5; do
    [ ! -s "$log" ] || break
    sleep 1
done
test -s "$log"
test "$(stat -c %a "$(dirname "$log")")" = 750
test "$(stat -c %a "$log")" = 640
rc-service "$service" status
uid=$(id -u "$service")
supervisor=$(cat "/run/$service.pid")
child=$(cat "/proc/$supervisor/task/$supervisor/children")
# The supervisor creates one child, which must drop privilege before running Python.
status="/proc/${child% }/status"
grep -Eq "^Uid:[[:space:]]+$uid[[:space:]]+$uid[[:space:]]+$uid[[:space:]]+$uid$" "$status"
grep -Eq '^CapEff:[[:space:]]+0+$' "$status"
grep -Eq '^NoNewPrivs:[[:space:]]+1$' "$status"
python3 -c 'import json, sys; event = json.loads(open(sys.argv[1]).readline()); assert event["openedr_event"] == "process.observed" and len(event["openedr_event_id"]) == 64' "$log"

first_event=$(head -n 1 "$log")
apk --no-network add "$packages/$service-0.0.2-r0.apk"
apk --no-network list --installed "$service" | grep -q "^$service-0\.0\.2-r0 "
rc-service "$service" restart
rc-service "$service" status
test "$(cat "/run/$service.pid")" != "$supervisor"
test "$(head -n 1 "$log")" = "$first_event"

rc-update add "$service" default
apk --no-network del "$service"
test ! -e "/etc/init.d/$service"
test ! -e "/etc/runlevels/default/$service"
test ! -e "/run/$service.pid"
test "$(head -n 1 "$log")" = "$first_event"

apk --no-network add "$packages/$service-0.0.2-r0.apk"
apk --no-network del "$service"
test ! -e "/etc/init.d/$service"
test "$(head -n 1 "$log")" = "$first_event"
