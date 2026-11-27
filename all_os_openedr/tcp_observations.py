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
MAX_ACCOUNT_EVENTS_PER_SECOND = 64
MAX_ACTOR_EVENTS_PER_SECOND = 32
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
            or min(first_seen, pid, netns) <= 0
            or stamp < first_seen
            or min(cpu, born) < 0
            or not 0 <= uid <= 0xffffffff
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
            # Keep large integers exact through the Wazuh JSON decoder.
            "openedr_network_namespace": str(netns),
            "openedr_network_monotonic_ns": str(stamp),
            "openedr_network_ip_version": local_address.version,
            "openedr_network_local_ip": str(local_address),
            "openedr_network_local_port": local,
            "openedr_pid": pid,
            "openedr_uid": str(uid),
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


class TCPBudget:
    def __init__(self, trace, clock=time.monotonic):
        self.trace = trace
        self.clock = clock
        self.second = -1
        self.events = 0
        self.accounts = {}
        self.actors = {}
        self.gaps = set()

    def admit(self, event):
        second = int(self.clock())
        if second != self.second:
            self.second, self.events = second, 0
            self.accounts.clear()
            self.actors.clear()
            self.gaps.clear()
        reason = event.get("openedr_gap_reason")
        if reason == "tcp_trace_stopped":
            return event
        if reason:
            if reason in self.gaps:
                return None
            self.gaps.add(reason)
            return event
        account, actor = event["openedr_uid"], event["openedr_file_actor_id"]
        account_count, actor_count = self.accounts.get(account, 0), self.actors.get(actor, 0)
        if (self.events >= MAX_EVENTS_PER_SECOND or account_count >= MAX_ACCOUNT_EVENTS_PER_SECOND
                or actor_count >= MAX_ACTOR_EVENTS_PER_SECOND):
            reason = "tcp_output_rate_limit"
            if reason in self.gaps:
                return None
            self.gaps.add(reason)
            return self.trace.gap(reason)
        self.accounts[account] = account_count + 1
        self.actors[actor] = actor_count + 1
        self.events += 1
        return event


def store_records(trace, stream):
    budget = TCPBudget(trace)
    for record in trace.records(stream):
        event = budget.admit(record)
        if event is None:
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
