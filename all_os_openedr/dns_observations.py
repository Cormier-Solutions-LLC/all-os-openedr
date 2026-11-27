"""Collect process-attributed outbound DNS questions on Linux."""

import ipaddress
from pathlib import Path

from .network_trace import NetworkTrace, run_sensor


PROGRAM = "/usr/share/all-os-openedr/network/dns-observations.bt"
OUTPUT = Path("/var/log/all-os-openedr-dns/events.jsonl")
QUESTION_TYPES = {1: "A", 28: "AAAA"}
NAME_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyz0123456789-_")


def dns_name(wire):
    if not 1 <= len(wire) <= 255:
        raise ValueError("Invalid DNS name length")
    labels = []
    offset = 0
    while offset < len(wire):
        size = wire[offset]
        offset += 1
        if size == 0 and offset == len(wire):
            return ".".join(labels) or "."
        if not 1 <= size <= 63 or offset + size >= len(wire):
            break
        label = wire[offset:offset + size].lower()
        labels.append("".join(chr(byte) if byte in NAME_BYTES else f"\\{byte:03d}" for byte in label))
        offset += size
    raise ValueError("Invalid uncompressed DNS question name")


class DNSTrace(NetworkTrace):
    protocol = "dns"

    def parse(self, data):
        if data == "nonlinear\n":
            return self.gap("nonlinear_question")
        stamp, cpu, pid, born, uid, netns, port, source, target, qtype, comm, name = data.rstrip("\n").split("\t")
        stamp, cpu, pid, born, uid, netns, port, qtype = map(int, (stamp, cpu, pid, born, uid, netns, port, qtype))
        local, resolver = ipaddress.ip_address(source), ipaddress.ip_address(target)
        question_type = QUESTION_TYPES.get(qtype)
        if cpu < 0 or not 1 <= port <= 65535 or local.version != resolver.version or question_type is None:
            raise ValueError("Invalid DNS question fields")
        return {
            **self.event("network.dns_query", f"{stamp}:{cpu}:{pid}"),
            **self.actor(stamp, netns, pid, uid, born, bytes.fromhex(comm)),
            "openedr_network_direction": "outbound",
            "openedr_network_transport": "udp",
            "openedr_network_ip_version": local.version,
            "openedr_network_local_ip": str(local),
            "openedr_network_local_port": port,
            "openedr_network_remote_ip": str(resolver),
            "openedr_network_remote_port": 53,
            "openedr_dns_name": dns_name(bytes.fromhex(name)),
            "openedr_dns_type": question_type,
        }


def main():
    return run_sensor(DNSTrace, PROGRAM, OUTPUT, {"BPFTRACE_MAX_STRLEN": "320"})


if __name__ == "__main__":
    raise SystemExit(main())
