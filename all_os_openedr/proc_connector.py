"""Read Linux kernel task lifecycle events from the process connector."""

import errno
import hashlib
import secrets
import select
import socket
import struct
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


NETLINK_CONNECTOR = 11
PROC_GROUP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLMSG_OVERRUN = 4
LISTEN = 1
IGNORE = 2
FORK = 1
EXEC = 2
EXIT = 0x80000000
NETLINK = struct.Struct("=IHHII")
CONNECTOR = struct.Struct("=IIIIHH")
PROC = struct.Struct("=IIQ")
U32_MASK = (1 << 32) - 1


class StreamGap(Exception):
    """Kernel data was dropped or could not be interpreted."""


@dataclass
class ProcessLifetime:
    identity: str
    birth_ns: int
    members: set[int]


def control_request(port, operation, nonce):
    body = CONNECTOR.pack(PROC_GROUP, PROC_GROUP, 0, nonce, 4, 0) + struct.pack("=I", operation)
    return NETLINK.pack(NETLINK.size + len(body), NLMSG_DONE, 0, 0, port) + body


def proc_records(datagram):
    offset = 0
    while offset < len(datagram):
        if len(datagram) - offset < NETLINK.size:
            raise StreamGap("invalid_datagram")
        length, message_type, _, _, _ = NETLINK.unpack_from(datagram, offset)
        end = offset + length
        if length < NETLINK.size or end > len(datagram):
            raise StreamGap("invalid_datagram")
        body = datagram[offset + NETLINK.size:end]
        offset += (length + 3) & ~3
        if message_type == NLMSG_OVERRUN:
            raise StreamGap("kernel_overrun")
        if message_type == NLMSG_ERROR:
            if len(body) < 4:
                raise StreamGap("invalid_datagram")
            error = struct.unpack_from("=i", body)[0]
            if error == -errno.ENOBUFS:
                raise StreamGap("kernel_overrun")
            if error:
                raise OSError(-error, "process connector rejected a request")
            continue
        if message_type != NLMSG_DONE:
            continue
        if len(body) < CONNECTOR.size:
            raise StreamGap("invalid_datagram")
        index, value, sequence, ack, size, _ = CONNECTOR.unpack_from(body)
        if (index, value) != (PROC_GROUP, PROC_GROUP):
            continue
        if size < PROC.size or size != len(body) - CONNECTOR.size:
            raise StreamGap("invalid_datagram")
        kind, cpu, stamp = PROC.unpack_from(body, CONNECTOR.size)
        yield kind, cpu, sequence, ack, stamp, body[CONNECTOR.size + PROC.size:]


class Lifecycle:
    def __init__(self, boot_id, host):
        self.boot_id = boot_id
        self.host = host
        self.stream_id = uuid.uuid4().hex
        self.processes = {}
        self.sequences = {}

    def event(self, name, event_id):
        return {
            "openedr_source": "all-os-openedr",
            "openedr_schema": 1,
            "openedr_event": name,
            "openedr_event_id": event_id,
            "openedr_host": self.host,
            "openedr_boot_id": self.boot_id,
            "openedr_stream_id": self.stream_id,
            "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }

    def gap(self, reason, cpu=None, count=None):
        self.processes.clear()
        event = self.event("process.stream_gap", uuid.uuid4().hex)
        event["openedr_gap_reason"] = reason
        if cpu is not None:
            event["openedr_kernel_cpu"] = cpu
        if count is not None:
            event["openedr_missing_events"] = count
        return event

    def identity(self, pid, stamp):
        return hashlib.sha256(f"{self.boot_id}:connector:leader:{pid}:{stamp}".encode()).hexdigest()

    def process_at(self, pid, stamp):
        process = self.processes.get(pid)
        if process is not None and process.birth_ns <= stamp:
            return process
        return None

    def accept(self, record):
        kind, cpu, sequence, _, stamp, payload = record
        previous = self.sequences.get(cpu)
        self.sequences[cpu] = sequence
        if previous is not None:
            missing = (sequence - previous - 1) & U32_MASK
            if missing >= 1 << 31:
                yield self.gap("sequence_reset", cpu)
            elif missing:
                yield self.gap("sequence_gap", cpu, missing)

        if kind not in (FORK, EXEC, EXIT):
            return
        required = {FORK: 16, EXEC: 8, EXIT: 24}[kind]
        if len(payload) < required:
            yield self.gap("invalid_payload", cpu)
            return
        parent_pid = parent_tid = 0
        if kind == FORK:
            parent_tid, parent_pid, tid, pid = struct.unpack_from("=iiii", payload)
            name = "process.fork"
        elif kind == EXEC:
            tid, pid = struct.unpack_from("=ii", payload)
            name = "process.exec"
        else:
            tid, pid, wait_status, _, parent_tid, parent_pid = struct.unpack_from("=iiIIii", payload)
            name = "process.task_exit"
        if pid < 1 or tid < 1:
            return
        leader = pid == tid
        parent = self.process_at(parent_pid, stamp)
        if kind == FORK and leader:
            current = self.processes.get(pid)
            if current is None or current.birth_ns <= stamp:
                self.processes[pid] = ProcessLifetime(self.identity(pid, stamp), stamp, {tid})
        process = self.process_at(pid, stamp)
        if process is not None:
            if kind == FORK:
                process.members.add(tid)
            elif kind == EXEC:
                # A successful exec replaces the other threads in this group.
                process.members = {tid}
            else:
                process.members.discard(tid)
                if not process.members:
                    self.processes.pop(pid)

        key = f"{self.boot_id}:connector:{cpu}:{sequence}:{stamp}"
        event = self.event(name, hashlib.sha256(key.encode()).hexdigest())
        event.update({
            "openedr_pid": pid,
            "openedr_tid": tid,
            "openedr_thread_group_leader": leader,
            "openedr_kernel_cpu": cpu,
            "openedr_kernel_sequence": sequence,
            "openedr_kernel_monotonic_ns": stamp,
        })
        if process is not None:
            event["openedr_process_id"] = process.identity
        if kind == EXIT:
            event["openedr_wait_status"] = wait_status
        if parent_pid > 0:
            event["openedr_parent_pid"] = parent_pid
            event["openedr_parent_tid"] = parent_tid
        if parent is not None:
            event["openedr_parent_process_id"] = parent.identity
        yield event


def receive(channel):
    try:
        data, _, flags, address = channel.recvmsg(65536)
    except OSError as error:
        if error.errno == errno.ENOBUFS:
            raise StreamGap("kernel_overrun") from error
        raise
    if address[0] != 0:
        return ()
    if flags & socket.MSG_TRUNC:
        raise StreamGap("truncated_datagram")
    return proc_records(data)


class LinuxProcConnector:
    def stream(self):
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        tracker = Lifecycle(boot_id, socket.gethostname())
        with socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR) as channel:
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
            channel.bind((0, PROC_GROUP))
            port = channel.getsockname()[0]
            nonce = secrets.randbits(31)
            channel.sendto(control_request(port, LISTEN, nonce), (0, 0))
            try:
                self.confirm_subscription(channel, nonce)
                channel.setblocking(False)
                yield [tracker.event("process.stream_started", tracker.stream_id)]
                recovering = False
                while True:
                    select.select([channel], [], [])
                    batch = []
                    for _ in range(128):
                        try:
                            records = receive(channel)
                            if not recovering:
                                for record in records:
                                    batch.extend(tracker.accept(record))
                        except BlockingIOError:
                            recovering = False
                            break
                        except StreamGap as error:
                            if not recovering:
                                tracker.sequences.clear()
                                batch.append(tracker.gap(str(error)))
                            recovering = True
                    if batch:
                        yield batch
            finally:
                with suppress(OSError):
                    channel.sendto(control_request(port, IGNORE, nonce), (0, 0))

    @staticmethod
    def confirm_subscription(channel, nonce):
        deadline = time.monotonic() + 5
        while (remaining := deadline - time.monotonic()) > 0:
            channel.settimeout(remaining)
            try:
                for kind, _, _, ack, _, payload in receive(channel):
                    if kind == 0 and ack == nonce + 1:
                        if len(payload) < 4:
                            raise StreamGap("invalid_ack")
                        error = struct.unpack_from("=I", payload)[0]
                        if error:
                            raise OSError(error, "unable to subscribe to the process connector")
                        return
            except StreamGap as error:
                raise OSError("invalid process connector subscription response") from error
            except TimeoutError:
                break
        raise OSError("process connector did not acknowledge the subscription; check the host kernel and namespaces")
