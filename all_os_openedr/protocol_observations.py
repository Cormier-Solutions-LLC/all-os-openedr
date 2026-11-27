"""Collect process-attributed HTTP and FTP metadata from Linux TCP streams."""

import ctypes as c
import errno
import ipaddress
import json
import os
import struct
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from .application_protocols import FTPRequests, HTTPRequests
from .evidence_log import exclusive_log, rotate_evidence
from .ima_audit import append
from .network_trace import LOG_BACKUPS, LOG_MAX_BYTES, NetworkTrace, ObservationBudget, identity


OBJECT = "/run/all-os-openedr-protocol/protocol.bpf.o"
OUTPUT = Path("/var/log/all-os-openedr-protocol/events.jsonl")
CAPTURE_LIMIT = 4096
FLOW_LIMIT = 1024
ACCOUNT_FLOW_LIMIT = 128
IDLE_NS = 120_000_000_000
SYN, FIN, RST = 1, 2, 4
MASK = 0xffffffff


class Actor(c.Structure):
    _fields_ = [
        ("born", c.c_uint64), ("connected", c.c_uint64), ("pid", c.c_uint32),
        ("uid", c.c_uint32), ("netns", c.c_uint32),
        ("comm", c.c_uint8 * 16), ("seen", c.c_uint32),
    ]


class Packet(c.Structure):
    _fields_ = [
        ("cookie", c.c_uint64), ("stamp", c.c_uint64), ("actor", Actor),
        ("sequence", c.c_uint32), ("length", c.c_uint32), ("captured", c.c_uint16),
        ("local_port", c.c_uint16), ("peer_port", c.c_uint16), ("ip_version", c.c_uint8),
        ("incoming", c.c_uint8), ("flags", c.c_uint8), ("local", c.c_uint8 * 16), ("peer", c.c_uint8 * 16),
    ]

    @classmethod
    def unpack(cls, raw):
        if not HEADER_BYTES <= len(raw) <= HEADER_BYTES + CAPTURE_LIMIT:
            raise ValueError("Invalid application packet record size")
        header = cls.from_buffer_copy(raw[:HEADER_BYTES].ljust(c.sizeof(cls), b"\0"))
        data = raw[HEADER_BYTES:]
        if (
            header.cookie == 0 or header.stamp == 0 or header.ip_version not in {4, 6}
            or not 0 < header.actor.connected <= header.stamp
            or header.peer_port not in {21, 80} or header.local_port == 0
            or header.incoming not in {0, 1} or header.flags & ~(SYN | FIN | RST)
            or header.captured != len(data) or header.length < len(data)
        ):
            raise ValueError("Invalid application packet record fields")
        return header, data

    def tuple(self):
        width = 4 if self.ip_version == 4 else 16
        return (str(ipaddress.ip_address(bytes(self.local[:width]))), self.local_port,
                str(ipaddress.ip_address(bytes(self.peer[:width]))), self.peer_port)


HEADER_BYTES = Packet.peer.offset + 16
CLOSED_SOCKET = struct.Struct("=QQ")
RING_SAMPLE = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_void_p, c.c_size_t)


class Stream:
    def __init__(self):
        self.next = None

    def push(self, packet, payload, parser):
        start = (packet.sequence + bool(packet.flags & SYN)) & MASK
        if self.next is None:
            if packet.flags & SYN:
                self.next = start
            elif packet.length:
                raise ValueError("TCP handshake was not observed")
            else:
                return
        if not packet.length:
            return
        ahead = (start - self.next) & MASK
        if 0 < ahead < (1 << 31):
            raise ValueError("TCP segment arrived ahead of observed bytes")
        overlap = (self.next - start) & MASK
        if overlap >= packet.length:
            return
        self.next = (start + packet.length) & MASK
        if overlap < len(payload):
            yield from parser.feed(packet.incoming, payload[overlap:])
        unseen = packet.length - max(overlap, len(payload))
        if unseen:
            parser.skip(packet.incoming, unseen)


class Flow:
    def __init__(self, packet):
        self.endpoint = packet.tuple()
        self.stamp = packet.stamp
        self.uid = packet.actor.uid
        self.parser = HTTPRequests() if packet.peer_port == 80 else FTPRequests()
        self.streams = (Stream(), Stream())
        self.emitted = 0
        self.finished = [False, False]


class ProtocolTrace(NetworkTrace):
    protocol = "application"

    def __init__(self, boot_id, host, ticks):
        super().__init__(boot_id, host, ticks)
        self.flows = {}
        self.sweep_at = 0

    def receive_packet(self, raw):
        if len(raw) == CLOSED_SOCKET.size:
            self.flows.pop(CLOSED_SOCKET.unpack(raw), None)
            return
        packet, payload = Packet.unpack(raw)
        if packet.stamp >= self.sweep_at:
            self.flows = {cookie: flow for cookie, flow in self.flows.items() if packet.stamp - flow.stamp < IDLE_NS}
            self.sweep_at = packet.stamp + 1_000_000_000
        socket_key = packet.cookie, packet.actor.connected
        flow = self.flows.get(socket_key)
        if flow is None:
            if packet.incoming or not packet.flags & SYN:
                return
            if len(self.flows) >= FLOW_LIMIT:
                yield self.gap("flow_capacity")
                return
            if sum(flow.uid == packet.actor.uid for flow in self.flows.values()) >= ACCOUNT_FLOW_LIMIT:
                yield self.gap("account_flow_capacity")
                return
            flow = self.flows[socket_key] = Flow(packet)
        flow.stamp = max(flow.stamp, packet.stamp)
        try:
            if packet.tuple() != flow.endpoint:
                raise ValueError("TCP tuple changed on a tracked socket")
            for fields in flow.streams[packet.incoming].push(packet, payload, flow.parser):
                flow.emitted += 1
                local, local_port, peer, peer_port = flow.endpoint
                who = packet.actor
                yield {
                    **self.event("network.application_request",
                                 f"{packet.cookie}:{who.connected}:{packet.stamp}:{flow.emitted}"),
                    **self.actor(packet.stamp, who.netns, who.pid, who.uid, who.born, bytes(who.comm)),
                    "openedr_network_socket_id": identity(f"{self.boot_id}:socket-cookie:{packet.cookie}:{who.connected}"),
                    "openedr_network_direction": "outbound",
                    "openedr_network_transport": "tcp",
                    "openedr_network_attribution": "socket_connect_actor",
                    "openedr_network_ip_version": packet.ip_version,
                    "openedr_network_local_ip": local,
                    "openedr_network_local_port": local_port,
                    "openedr_network_remote_ip": peer,
                    "openedr_network_remote_port": peer_port,
                    **fields,
                }
        except ValueError:
            self.flows.pop(socket_key, None)
            yield self.gap("stream_discontinuity")
        if packet.flags & FIN:
            flow.finished[packet.incoming] = True
        if packet.flags & RST or all(flow.finished):
            self.flows.pop(socket_key, None)


def libbpf():
    library = c.CDLL("libbpf.so.1", use_errno=True)
    pointer, text, integer = c.c_void_p, c.c_char_p, c.c_int
    signatures = {
        "libbpf_get_error": (c.c_long, (pointer,)),
        "bpf_object__open_file": (pointer, (text, pointer)),
        "bpf_object__load": (integer, (pointer,)),
        "bpf_object__close": (None, (pointer,)),
        "bpf_object__find_program_by_name": (pointer, (pointer, text)),
        "bpf_object__find_map_fd_by_name": (integer, (pointer, text)),
        "bpf_program__attach": (pointer, (pointer,)),
        "bpf_program__attach_cgroup": (pointer, (pointer, integer)),
        "bpf_link__destroy": (integer, (pointer,)),
        "bpf_map_lookup_elem": (integer, (integer, pointer, pointer)),
        "ring_buffer__new": (pointer, (integer, RING_SAMPLE, pointer, pointer)),
        "ring_buffer__poll": (integer, (pointer, integer)),
        "ring_buffer__free": (None, (pointer,)),
    }
    for name, (result, args) in signatures.items():
        function = getattr(library, name)
        function.restype, function.argtypes = result, args
    return library


def require(result, operation):
    if result < 0:
        code = -result if result < -1 else c.get_errno() or errno.EIO
        raise OSError(code, operation)


def require_pointer(library, value, operation):
    require(library.libbpf_get_error(value), operation)
    if not value:
        raise OSError(c.get_errno() or errno.EINVAL, operation)
    return value


def watch(trace):
    library = libbpf()
    budget = ObservationBudget(trace)
    failure = None

    def publish(record):
        if event := budget.admit(record):
            size = len(json.dumps(event, separators=(",", ":"))) + 1
            rotate_evidence(OUTPUT, size, LOG_MAX_BYTES, LOG_BACKUPS)
            append(event, log=OUTPUT)

    @RING_SAMPLE
    def sample(context, address, size):
        nonlocal failure
        try:
            try:
                if size != CLOSED_SOCKET.size and not HEADER_BYTES <= size <= HEADER_BYTES + CAPTURE_LIMIT:
                    raise ValueError("Unexpected kernel sample size")
                for event in trace.receive_packet(c.string_at(address, size)):
                    publish(event)
            except ValueError:
                trace.flows.clear()
                publish(trace.gap("invalid_trace_record"))
        except OSError as error:
            failure = error
            return -errno.EIO
        return 0

    with exclusive_log(OUTPUT), ExitStack() as cleanup:
        obj = require_pointer(library, library.bpf_object__open_file(os.fsencode(OBJECT), None), "Open protocol probes")
        cleanup.callback(library.bpf_object__close, obj)
        require(library.bpf_object__load(obj), "Load protocol probes")
        lost = library.bpf_object__find_map_fd_by_name(obj, b"lost")
        require(lost, "Find protocol loss counter")
        packets = library.bpf_object__find_map_fd_by_name(obj, b"packets")
        require(packets, "Find protocol ring buffer")
        ring = require_pointer(library, library.ring_buffer__new(packets, sample, None, None), "Open protocol ring buffer")
        cleanup.callback(library.ring_buffer__free, ring)
        group = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        cleanup.callback(os.close, group)
        for name in (b"observe_connect", b"observe_close", b"forget_socket", b"protocol_egress", b"protocol_ingress"):
            program = require_pointer(library, library.bpf_object__find_program_by_name(obj, name), "Find protocol probe")
            link = library.bpf_program__attach_cgroup(program, group) if name.startswith(b"protocol_") else library.bpf_program__attach(program)
            cleanup.callback(library.bpf_link__destroy, require_pointer(library, link, f"Attach {name.decode()}"))
        loss_counts = [0, 0]
        count = c.c_uint64()
        while True:
            status = library.ring_buffer__poll(ring, 250)
            if failure:
                raise failure
            if status != -errno.EINTR:
                require(status, "Read protocol ring buffer")
            for index, reason in enumerate(("kernel_events_lost", "packet_rate_limit")):
                key = c.c_uint(index)
                require(library.bpf_map_lookup_elem(lost, c.byref(key), c.byref(count)), "Read protocol loss counter")
                if count.value != loss_counts[index]:
                    loss_counts[index] = count.value
                    if index == 0:
                        trace.flows.clear()
                    publish(trace.gap(reason))


def main():
    try:
        if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
            raise ValueError("The protocol sensor requires a unified cgroup hierarchy")
        libc = c.CDLL(None, use_errno=True)
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
            raise OSError(c.get_errno(), "Disable protocol collector core dumps")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        trace = ProtocolTrace(boot, os.uname().nodename, os.sysconf("SC_CLK_TCK"))
        watch(trace)
    except (OSError, ValueError) as error:
        print(f"all-os-openedr-protocol: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
