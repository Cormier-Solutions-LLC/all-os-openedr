"""Collect process-attributed Linux TCP connection evidence."""

import ipaddress
from pathlib import Path

from .network_trace import NetworkTrace, identity, run_sensor


PROGRAM = "/usr/share/all-os-openedr/network/tcp-observations.bt"
OUTPUT = Path("/var/log/all-os-openedr-tcp/events.jsonl")
DIRECTIONS = {1: "outbound", 2: "inbound", 3: "listener"}
PHASES = {"1": "connecting", "2": "established", "3": "accepted", "4": "listening", "5": "closed"}
PHASE_DIRECTIONS = {
    "connecting": {1}, "established": {1}, "accepted": {2}, "listening": {3}, "closed": {1, 2, 3},
}


class TCPTrace(NetworkTrace):
    protocol = "tcp"

    def parse(self, data):
        if data == "map_full\n":
            return self.gap("socket_tracking_capacity")
        fields = data.split()
        if len(fields) != 29:
            raise ValueError("Unexpected TCP trace field count")
        phase_code, first_seen, cpu, stamp, pid, born, direction = fields[:7]
        netns, local, remote, source, target, uid = fields[-6:]
        first_seen, cpu, stamp, pid, born, direction, netns, local, remote, uid = map(
            int, (first_seen, cpu, stamp, pid, born, direction, netns, local, remote, uid),
        )
        phase = PHASES.get(phase_code)
        local_address, remote_address = ipaddress.ip_address(source), ipaddress.ip_address(target)
        raw_comm = bytes.fromhex("".join(fields[7:-6]))
        if (
            direction not in PHASE_DIRECTIONS.get(phase, ())
            or first_seen <= 0
            or stamp < first_seen
            or cpu < 0
            or local_address.version != remote_address.version
            or not 1 <= local <= 65535
            or not 0 <= remote <= 65535
            or (direction == 3 and (remote != 0 or not remote_address.is_unspecified))
            or (direction != 3 and remote == 0)
        ):
            raise ValueError("Invalid TCP trace fields")
        key = f"{first_seen}:{cpu}:{pid}"
        event = {
            **self.event(f"network.tcp_{phase}", f"{key}:{stamp}:{phase}"),
            "openedr_network_socket_id": identity(f"{self.boot_id}:tcp-socket:{key}"),
            "openedr_network_direction": DIRECTIONS[direction],
            **self.actor(stamp, netns, pid, uid, born, raw_comm),
            "openedr_network_ip_version": local_address.version,
            "openedr_network_local_ip": str(local_address),
            "openedr_network_local_port": local,
        }
        if direction != 3:
            event.update({"openedr_network_remote_ip": str(remote_address), "openedr_network_remote_port": remote})
        return event


def main():
    return run_sensor(TCPTrace, PROGRAM, OUTPUT, {"BPFTRACE_MAX_MAP_KEYS": "16384"})


if __name__ == "__main__":
    raise SystemExit(main())
