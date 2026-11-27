"""Collect process-attributed Linux TCP connection evidence."""

import hashlib
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .evidence_log import exclusive_log, rotate_evidence
from .file_provenance import linux_actor_id, visible_text
from .ima_audit import append


PROGRAM = "/usr/share/all-os-openedr/network/tcp-observations.bt"
OUTPUT = Path("/var/log/all-os-openedr-tcp/events.jsonl")
MAX_RECORD = 2048
MAX_EVENTS_PER_SECOND = 128
LOG_MAX_BYTES = 16 * 1024 * 1024
LOG_BACKUPS = 3
DIRECTIONS = {1: "outbound", 2: "inbound", 3: "listener"}
PHASES = {"1": "connecting", "2": "established", "3": "accepted", "4": "listening", "5": "closed"}
PHASE_DIRECTIONS = {
    "connecting": {1}, "established": {1}, "accepted": {2}, "listening": {3}, "closed": {1, 2, 3},
}


def identity(value):
    return hashlib.sha256(value.encode()).hexdigest()


class TCPTrace:
    def __init__(self, boot_id, host, ticks):
        self.boot_id = boot_id
        self.host = host
        self.ticks = ticks

    def event(self, kind, key):
        return {
            "openedr_schema": 1,
            "openedr_event": kind,
            "openedr_event_id": identity(f"{self.boot_id}:tcp:{key}"),
            "openedr_source": "all-os-openedr",
            "openedr_host": self.host,
            "openedr_boot_id": self.boot_id,
            "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }

    def gap(self, reason):
        return {
            **self.event("network.tcp_stream_gap", f"{reason}:{time.monotonic_ns()}"),
            "openedr_gap_reason": reason,
        }

    def receive(self, line):
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("Expected a trace record")
            if message.get("type") == "lost_events":
                return self.gap("tcp_kernel_events_lost")
            if message.get("type") != "printf":
                return None
            data = message.get("data")
            if not isinstance(data, str):
                raise ValueError("Expected the trace record body")
            if data == "map_full\n":
                return self.gap("tcp_socket_tracking_capacity")
            return self.parse(data)
        except (ValueError, UnicodeError):
            return self.gap("tcp_invalid_trace_record")

    def parse(self, data):
        fields = data.split()
        if len(fields) != 28:
            raise ValueError("Unexpected TCP trace field count")
        phase_code, first_seen, cpu, stamp, pid, born, direction = fields[:7]
        netns, local, remote, source, target = fields[-5:]
        first_seen, cpu, stamp, pid, born, direction, netns, local, remote = map(
            int, (first_seen, cpu, stamp, pid, born, direction, netns, local, remote),
        )
        phase = PHASES.get(phase_code)
        local_address, remote_address = ipaddress.ip_address(source), ipaddress.ip_address(target)
        raw_comm = bytes.fromhex("".join(fields[7:-5]))
        if (
            direction not in PHASE_DIRECTIONS.get(phase, ())
            or min(first_seen, pid, netns) <= 0
            or stamp < first_seen
            or min(cpu, born) < 0
            or len(raw_comm) != 16
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
            "openedr_network_namespace": netns,
            "openedr_network_monotonic_ns": stamp,
            "openedr_network_ip_version": local_address.version,
            "openedr_network_local_ip": str(local_address),
            "openedr_network_local_port": local,
            "openedr_pid": pid,
            "openedr_file_actor_id": linux_actor_id(self.boot_id, pid, born * self.ticks // 1_000_000_000),
            "openedr_process": visible_text(raw_comm.split(b"\0", 1)[0]),
        }
        if direction != 3:
            event.update({"openedr_network_remote_ip": str(remote_address), "openedr_network_remote_port": remote})
        return event

    def records(self, stream):
        while line := stream.readline(MAX_RECORD + 1):
            if len(line) > MAX_RECORD:
                yield self.gap("tcp_invalid_trace_record")
                return
            if record := self.receive(line):
                yield record
        yield self.gap("tcp_trace_stopped")


def store_records(trace, stream):
    second, events = -1, 0
    for event in trace.records(stream):
        now = int(time.monotonic())
        if now != second:
            second, events = now, 0
        events += 1
        if event.get("openedr_gap_reason") != "tcp_trace_stopped":
            if events == MAX_EVENTS_PER_SECOND + 1:
                event = trace.gap("tcp_output_rate_limit")
            elif events > MAX_EVENTS_PER_SECOND:
                continue
        size = len(json.dumps(event, separators=(",", ":"))) + 1
        rotate_evidence(OUTPUT, size, LOG_MAX_BYTES, LOG_BACKUPS)
        append(event, log=OUTPUT)


def main():
    try:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("The TCP sensor requires Debian 13 amd64 with kernel BTF")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        trace = TCPTrace(boot, socket.gethostname(), os.sysconf("SC_CLK_TCK"))
        command = ["/usr/bin/bpftrace", "-q", "-B", "line", "-f", "json", PROGRAM]
        environment = {**os.environ, "BPFTRACE_MAX_MAP_KEYS": "16384"}
        with exclusive_log(OUTPUT), subprocess.Popen(command, stdout=subprocess.PIPE, env=environment) as child:
            try:
                store_records(trace, child.stdout)
            finally:
                if child.poll() is None:
                    child.terminate()
        return 1
    except (OSError, ValueError) as error:
        print(f"all-os-openedr-tcp: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
