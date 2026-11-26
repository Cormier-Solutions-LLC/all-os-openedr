"""Poll Linux process metadata and write an event stream for a local forwarder."""

import argparse
import hashlib
import json
import math
import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .executable import ExecutableOpen
from .file_provenance import FileProvenance
from .plugins import API_VERSION, Plugin, Registry
from .proc_connector import LinuxProcConnector


class LinuxProcesses:
    def __init__(self, proc=Path("/proc")):
        self.proc = proc
        self.host = socket.gethostname()
        self.boot_id = (proc / "sys/kernel/random/boot_id").read_text().strip()
        self.seen = set()

    def poll(self):
        current = set()
        events = []
        for path in self.proc.iterdir():
            if not path.name.isdecimal():
                continue
            try:
                stat = (path / "stat").read_text(encoding="utf-8", errors="replace")
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            opening = stat.find("(")
            closing = stat.rfind(")")
            if opening == -1 or closing <= opening:
                continue
            fields = stat[closing + 1:].split()
            if len(fields) < 20 or not fields[19].isdigit():
                continue
            pid = int(path.name)
            start_ticks = int(fields[19])
            identity = (pid, start_ticks)
            current.add(identity)
            if identity in self.seen:
                continue
            event_id = hashlib.sha256(f"{self.boot_id}:{pid}:{start_ticks}".encode()).hexdigest()
            events.append({
                "openedr_source": "all-os-openedr",
                "openedr_schema": 1,
                "openedr_event": "process.observed",
                "openedr_event_id": event_id,
                "openedr_host": self.host,
                "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "openedr_pid": pid,
                "openedr_process": stat[opening + 1:closing],
            })
        self.seen = current
        return events


class JsonLines:
    def __init__(self, output):
        self.output = Path(output)

    def write(self, events):
        if events:
            with self.output.open("a", encoding="utf-8") as stream:
                for event in events:
                    stream.write(json.dumps(event, separators=(",", ":")) + "\n")


PLUGINS = Registry({
    "linux-processes": Plugin("collector", API_VERSION, LinuxProcesses),
    "linux-proc-connector": Plugin("collector", API_VERSION, LinuxProcConnector),
    "linux-file-provenance": Plugin("collector", API_VERSION, FileProvenance),
    "linux-executable-open": Plugin("collector", API_VERSION, ExecutableOpen),
    "json-lines": Plugin("sink", API_VERSION, JsonLines),
})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collector", default="linux-processes")
    parser.add_argument("--sink", default="json-lines")
    parser.add_argument("--output", default="/var/log/all-os-openedr/events.jsonl")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--filesystem", help="mounted filesystem root for the selected fanotify collector")
    parser.add_argument("--executable-catalog", help="local SHA-256 verdict catalog for linux-executable-open")
    parser.add_argument("--once", action="store_true")
    options = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("The process collector requires Linux")
    if not math.isfinite(options.interval) or options.interval < 0.25:
        parser.error("--interval must be finite and at least 0.25 seconds")
    filesystem_collectors = {"linux-file-provenance", "linux-executable-open"}
    if options.collector in filesystem_collectors and options.filesystem is None:
        parser.error(f"{options.collector} requires --filesystem")
    if options.filesystem is not None and options.collector not in filesystem_collectors:
        parser.error("--filesystem applies to the built-in fanotify collectors")
    if options.executable_catalog is not None and options.collector != "linux-executable-open":
        parser.error("--executable-catalog applies to linux-executable-open")
    os.umask(0o027)
    try:
        collector_options = (
            {"filesystem": options.filesystem, "output": options.output} if options.filesystem is not None else {}
        )
        if options.executable_catalog is not None:
            collector_options["executable_catalog"] = options.executable_catalog
        collector = PLUGINS.create(options.collector, "collector", **collector_options)
        sink = PLUGINS.create(options.sink, "sink", output=options.output)
        stream = getattr(collector, "stream", None)
        if callable(stream):
            if options.once:
                parser.error("--once requires a sampling collector")
            for batch in stream():
                sink.write(batch)
            return 0
        while True:
            sink.write(collector.poll())
            if options.once:
                return 0
            time.sleep(options.interval)
    except (OSError, ValueError) as error:
        print(f"all-os-openedr: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
