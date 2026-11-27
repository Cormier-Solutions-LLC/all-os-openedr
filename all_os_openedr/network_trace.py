"""Common framing, attribution and delivery for Debian socket sensors."""

import hashlib
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


MAX_RECORD = 2048
MAX_EVENTS_PER_SECOND = 128
MAX_ACCOUNT_EVENTS_PER_SECOND = 64
MAX_ACTOR_EVENTS_PER_SECOND = 32
LOG_MAX_BYTES = 16 * 1024 * 1024
LOG_BACKUPS = 3


def identity(value):
    return hashlib.sha256(value.encode()).hexdigest()


class NetworkTrace:
    def __init__(self, boot_id, host, ticks):
        self.boot_id = boot_id
        self.host = host
        self.ticks = ticks

    def event(self, kind, key):
        return {
            "openedr_schema": 1,
            "openedr_event": kind,
            "openedr_event_id": identity(f"{self.boot_id}:{self.protocol}:{key}"),
            "openedr_source": "all-os-openedr",
            "openedr_host": self.host,
            "openedr_boot_id": self.boot_id,
            "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }

    def actor(self, stamp, namespace, pid, uid, born, comm):
        if (
            min(stamp, namespace, pid) <= 0
            or born < 0
            or not 0 <= uid <= 0xffffffff
            or len(comm) != 16
        ):
            raise ValueError("Invalid socket actor fields")
        return {
            # Keep large integers exact through the Wazuh JSON decoder.
            "openedr_network_namespace": str(namespace),
            "openedr_network_monotonic_ns": str(stamp),
            "openedr_pid": pid,
            "openedr_uid": str(uid),
            "openedr_file_actor_id": linux_actor_id(self.boot_id, pid, born * self.ticks // 1_000_000_000),
            "openedr_process": visible_text(comm.split(b"\0", 1)[0]),
        }

    def gap(self, cause):
        reason = f"{self.protocol}_{cause}"
        return {
            **self.event(f"network.{self.protocol}_stream_gap", f"{reason}:{time.monotonic_ns()}"),
            "openedr_gap_reason": reason,
        }

    def receive(self, line):
        try:
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("Expected a trace record")
            if message.get("type") == "lost_events":
                return self.gap("kernel_events_lost")
            if message.get("type") != "printf":
                return None
            data = message.get("data")
            if not isinstance(data, str):
                raise ValueError("Expected the trace record body")
            return self.parse(data)
        except (ValueError, UnicodeError):
            return self.gap("invalid_trace_record")

    def records(self, stream):
        while line := stream.readline(MAX_RECORD + 1):
            if len(line) > MAX_RECORD:
                yield self.gap("invalid_trace_record")
                return
            if record := self.receive(line):
                yield record
        yield self.gap("trace_stopped")


class ObservationBudget:
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
        if reason == f"{self.trace.protocol}_trace_stopped":
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
            reason = f"{self.trace.protocol}_output_rate_limit"
            if reason in self.gaps:
                return None
            self.gaps.add(reason)
            return self.trace.gap("output_rate_limit")
        self.accounts[account] = account_count + 1
        self.actors[actor] = actor_count + 1
        self.events += 1
        return event


def run_sensor(trace_type, program, output, settings):
    try:
        if platform.system() != "Linux" or platform.machine() != "x86_64":
            raise ValueError("This sensor requires Debian 13 amd64 with kernel BTF")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        trace = trace_type(boot, socket.gethostname(), os.sysconf("SC_CLK_TCK"))
        budget = ObservationBudget(trace)
        command = ["/usr/bin/bpftrace", "-q", "-B", "line", "-f", "json", program]
        environment = {**os.environ, **settings}
        with exclusive_log(output), subprocess.Popen(command, stdout=subprocess.PIPE, env=environment) as child:
            try:
                for record in trace.records(child.stdout):
                    if (event := budget.admit(record)) is not None:
                        size = len(json.dumps(event, separators=(",", ":"))) + 1
                        rotate_evidence(output, size, LOG_MAX_BYTES, LOG_BACKUPS)
                        append(event, log=output)
            finally:
                if child.poll() is None:
                    child.terminate()
        return 1
    except (OSError, ValueError) as error:
        print(f"all-os-openedr-{trace_type.protocol}: {error}", file=sys.stderr)
        return 1
