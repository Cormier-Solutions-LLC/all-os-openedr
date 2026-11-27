"""Authorize Linux network isolation and managed executable quarantine."""

import argparse
import base64
import ctypes
import errno
import fcntl
import ipaddress
import json
import os
import pwd
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from .apparmor_policy import trusted_file
from .executable import SHA256, file_version, inspect_descriptor
from .ima_policy import open_candidate, select_filesystem


CONFIG = Path("/etc/all-os-openedr/response.json")
SIGNERS = CONFIG.with_name("response-signers")
AGENT_KEYS = Path("/var/ossec/etc/client.keys")
STATE = Path("/var/lib/all-os-openedr-response")
LOG = Path("/var/log/all-os-openedr-response/actions.jsonl")
NAMESPACE = "all-os-openedr-response-v1"
TABLE = "inet all_os_openedr_response"
TABLE_COMMENT = "all-os-openedr-response:"
MAX_DURATION = 900
MAX_DELIVERY_MS = 60_000
MAX_MESSAGE = 16_384
IDENTITY = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.@-]{0,63}")
ENDPOINT = re.compile(r"[0-9a-f]{32}")
AGENT = re.compile(r"(?!0+$)[0-9]{3,8}")
ALERT_ID = re.compile(r"[0-9]{1,20}\.[0-9]{1,20}")
VOLUME_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
QUARANTINE = ".openedr-quarantine"
FILE_ACTIONS = ("quarantine", "restore")
RENAME_NOREPLACE = 1


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def restricted_file(path, owners=(0,)):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(info.st_uid in owners and stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022,
                "unsafe_configuration_file")
        data = stream.read(MAX_MESSAGE + 1)
    require(len(data) <= MAX_MESSAGE, "configuration_too_large")
    return data


def private_directory(path, *, create=True):
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    require(info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o077,
            "unsafe_response_directory")


def fields(obj, expected, reason):
    require(isinstance(obj, dict) and obj.keys() == set(expected), reason)


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def load_config(*, check_enrollment=True):
    directory = CONFIG.parent.lstat()
    require(directory.st_uid == 0 and stat.S_ISDIR(directory.st_mode) and not directory.st_mode & 0o022,
            "unsafe_configuration_directory")
    config = json.loads(restricted_file(CONFIG))
    required = {"endpoint", "agent", "manager"}
    require(isinstance(config, dict) and required <= config.keys() <= required | {"quarantine"},
            "invalid_endpoint_config")
    require(matches(ENDPOINT, config["endpoint"]) and matches(AGENT, config["agent"]),
            "invalid_endpoint_config")
    if check_enrollment:
        keys_owner = pwd.getpwnam("wazuh").pw_uid
        require(restricted_file(AGENT_KEYS, (0, keys_owner)).split(maxsplit=1)[:1] == [config["agent"].encode()],
                "enrolled_agent_mismatch")
    manager = config["manager"]
    fields(manager, ("ip", "port"), "invalid_manager_config")
    require(isinstance(manager["ip"], str) and "%" not in manager["ip"], "invalid_manager_address")
    address = ipaddress.ip_address(manager["ip"])
    require(not (address.is_unspecified or address.is_multicast or address.is_loopback
                 or address.is_link_local or getattr(address, "ipv4_mapped", None)),
            "invalid_manager_address")
    port = manager["port"]
    require(type(port) is int and 1 <= port <= 65535, "invalid_manager_port")
    return config["endpoint"], config["agent"], address, port, config.get("quarantine")


def valid_quarantine_path(value):
    if not isinstance(value, str) or not value.isprintable() or len(value.encode("utf-8")) > 512 or "\\" in value:
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and str(path) == value and bool(path.parts)
            and path.parts[0] != QUARANTINE and ".." not in path.parts)


def decode_token(token):
    require(isinstance(token, str) and len(token) <= 8192, "invalid_approval")
    parts = token.split(".")
    require(len(parts) == 3 and parts[0] == "v1", "invalid_approval")
    payload, signature = (base64.b64decode(part, altchars=b"-_", validate=True) for part in parts[1:])
    request = json.loads(payload)
    required = ("action", "endpoint", "agent", "alert", "signer", "lease", "issued_ms", "seconds")
    require(isinstance(request, dict), "invalid_approval_fields")
    action = request.get("action")
    require(action in ("isolate", "release", *FILE_ACTIONS), "invalid_action")
    if action in FILE_ACTIONS:
        required += ("volume", "path", "sha256")
    fields(request, required, "invalid_approval_fields")
    for key, pattern in (("endpoint", ENDPOINT), ("agent", AGENT), ("alert", ALERT_ID),
                         ("signer", IDENTITY), ("lease", ENDPOINT)):
        require(matches(pattern, request[key]), f"invalid_approval_{key}")
    if action in FILE_ACTIONS:
        require(matches(VOLUME_ID, request["volume"]) and matches(SHA256, request["sha256"])
                and valid_quarantine_path(request["path"]), "invalid_quarantine_target")
    seconds = request["seconds"]
    require(type(seconds) is int and
            (1 <= seconds <= MAX_DURATION if action == "isolate" else seconds == 0),
            "invalid_duration")
    require(type(request["issued_ms"]) is int, "invalid_issued_time")
    return request, payload, signature


def approval_from_wazuh():
    line = sys.stdin.buffer.readline(MAX_MESSAGE + 1)
    require(len(line) <= MAX_MESSAGE and line.endswith(b"\n"), "invalid_wazuh_message")
    message = json.loads(line)
    require(isinstance(message, dict) and type(message.get("version")) is int
            and message["version"] == 1 and message.get("command") == "add", "invalid_wazuh_command")
    parameters = message.get("parameters")
    require(isinstance(parameters, dict), "missing_wazuh_parameters")
    args = parameters.get("extra_args")
    require(isinstance(args, list) and len(args) == 1, "missing_signed_approval")
    return decode_token(args[0])


def verify(request, payload, signature):
    keys = restricted_file(SIGNERS)
    with tempfile.TemporaryDirectory(dir=STATE) as directory:
        allowed = Path(directory, "allowed")
        signed = Path(directory, "signature")
        allowed.write_bytes(keys)
        signed.write_bytes(signature)
        result = subprocess.run(
            ["/usr/bin/ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", request["signer"],
             "-n", NAMESPACE, "-s", str(signed)],
            input=payload, capture_output=True, timeout=5, check=False,
        )
    require(result.returncode == 0, "bad_signature")


def nft(*args, script=None):
    return subprocess.run(["/usr/sbin/nft", *args], input=script, text=True,
                          capture_output=True, timeout=5, check=True).stdout


def owned_table():
    tables = json.loads(nft("-j", "list", "tables"))["nftables"]
    if not any(item.get("table", {}).get("family") == "inet"
               and item["table"].get("name") == "all_os_openedr_response" for item in tables):
        return None, False
    entries = json.loads(nft("-j", "list", "table", *TABLE.split()))["nftables"]
    comment = next((item["table"].get("comment", "") for item in entries if "table" in item), "")
    require(comment.startswith(TABLE_COMMENT) and matches(ENDPOINT, comment[len(TABLE_COMMENT):]),
            "foreign_firewall_table")
    lease_set = next((item["set"] for item in entries if item.get("set", {}).get("name") == "lease"), None)
    require(lease_set is not None, "invalid_isolation_table")
    return comment[len(TABLE_COMMENT):], bool(lease_set.get("elem"))


def isolation_rules(lease, address, port, milliseconds, replace):
    family = "ip" if address.version == 4 else "ip6"
    lines = [f"delete table {TABLE}"] if replace else []
    lines += [
        f'create table {TABLE} {{ comment "{TABLE_COMMENT}{lease}"; }}',
        f"add set {TABLE} lease {{ typeof meta nfproto; flags timeout; gc-interval 1s; }}",
        f"add element {TABLE} lease {{ ipv4 timeout {milliseconds}ms, ipv6 timeout {milliseconds}ms }}",
        f"add chain {TABLE} input {{ type filter hook input priority 50; policy accept; }}",
        f"add chain {TABLE} output {{ type filter hook output priority 50; policy accept; }}",
        f"add chain {TABLE} forward {{ type filter hook forward priority 50; policy accept; }}",
        f'add rule {TABLE} input iifname "lo" accept',
        f'add rule {TABLE} output oifname "lo" accept',
        f"add rule {TABLE} input {family} saddr {address} tcp sport {port} ct state established ct direction reply accept",
        f"add rule {TABLE} output {family} daddr {address} tcp dport {port} ct direction original accept",
        f"add rule {TABLE} input ip6 hoplimit 255 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept",
        f"add rule {TABLE} output ip6 hoplimit 255 icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept",
        *(f"add rule {TABLE} {chain} meta nfproto @lease counter drop" for chain in ("input", "output", "forward")),
    ]
    return "\n".join(lines) + "\n"


def audit(result, request=None, reason=None):
    file_action = request and request.get("action") in FILE_ACTIONS
    event = {
        "openedr_source": "all-os-openedr",
        "openedr_schema": 1,
        "openedr_event": "response.file_quarantine" if file_action else "response.network_isolation",
        "openedr_event_id": uuid.uuid4().hex,
        "openedr_host": socket.gethostname(),
        "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "openedr_response_result": result,
    }
    if request:
        event.update({f"openedr_response_{key}": request[key]
                      for key in ("action", "agent", "alert", "signer", "lease") if key in request})
        if file_action and "sha256" in request:
            event["openedr_response_file_sha256"] = request["sha256"]
            event["openedr_response_volume_uuid"] = request["volume"]
        duration = request.get("seconds", 0)
        if duration:
            event["openedr_response_deadline_ms"] = request["issued_ms"] + duration * 1000
    if reason:
        event["openedr_response_reason"] = reason
    descriptor = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(descriptor)
        require(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022,
                "unsafe_audit_file")
        line = (json.dumps(event, separators=(",", ":")) + "\n").encode()
        if os.write(descriptor, line) != len(line):
            raise OSError("short audit write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def consume_approval(request):
    watermark = STATE / "last_approval"
    try:
        previous = int(watermark.read_text(encoding="ascii"))
    except FileNotFoundError:
        previous = 0
    require(request["issued_ms"] > previous, "replayed_or_out_of_order")
    with tempfile.NamedTemporaryFile(dir=STATE, delete=False, mode="w", encoding="ascii") as temporary:
        path = Path(temporary.name)
        try:
            temporary.write(str(request["issued_ms"]) + "\n")
            temporary.flush()
            os.fsync(temporary.fileno())
            path.replace(watermark)
            descriptor = os.open(STATE, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        finally:
            path.unlink(missing_ok=True)


def approval_age(request):
    now_ms = time.time_ns() // 1_000_000
    age_ms = now_ms - request["issued_ms"]
    require(0 <= age_ms < MAX_DELIVERY_MS, "approval_outside_delivery_window")
    return age_ms


def apply(request, address, port):
    lease, active = owned_table()
    age_ms = approval_age(request)
    if request["action"] == "release":
        require(lease is None or lease == request["lease"], "wrong_active_lease")
        consume_approval(request)
        audit("authorized", request)
        if lease:
            nft("delete", "table", *TABLE.split())
        audit("released" if active else "already_inactive", request)
        return
    require(not active, "already_isolated")
    require(age_ms < request["seconds"] * 1000, "approval_expired")
    consume_approval(request)
    audit("authorized", request)
    elapsed_ms = max(age_ms, time.time_ns() // 1_000_000 - request["issued_ms"])
    remaining_ms = request["seconds"] * 1000 - elapsed_ms
    require(remaining_ms > 0, "approval_expired")
    nft("-f", "-", script=isolation_rules(request["lease"], address, port, remaining_ms, lease is not None))
    audit("isolated", request)


def open_directory(stack, path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    stack.callback(os.close, descriptor)
    return descriptor


def move_without_replacing(source, destination, metadata):
    require(destination.parent.resolve(strict=True) == destination.parent, "unsafe_quarantine_path")
    trusted_file(destination.parent)
    with ExitStack() as stack:
        source_dir = open_directory(stack, source.parent)
        destination_dir = open_directory(stack, destination.parent)
        current = os.stat(source.name, dir_fd=source_dir, follow_symlinks=False)
        require(os.path.samestat(metadata, current) and file_version(metadata) == file_version(current),
                "quarantine_source_changed")
        rename = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
        require(rename is not None, "atomic_rename_unavailable")
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(source_dir, os.fsencode(source.name), destination_dir, os.fsencode(destination.name),
                  RENAME_NOREPLACE) != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise ValueError("quarantine_destination_exists")
            raise OSError(error, os.strerror(error))
        os.fsync(destination_dir)
        os.fsync(source_dir)


def apply_file_response(request, config, *, local=False):
    require(config is not None, "quarantine_disabled")
    fields(config, ("filesystem", "uuid"), "invalid_quarantine_config")
    require(matches(VOLUME_ID, config["uuid"]) and isinstance(config["filesystem"], str)
            and Path(config["filesystem"]).is_absolute(), "invalid_quarantine_config")
    if local:
        request["volume"] = config["uuid"]
    else:
        approval_age(request)
    require(request["volume"] == config["uuid"], "quarantine_volume_mismatch")
    root, device, identity = select_filesystem(config["filesystem"])
    require(root == Path(config["filesystem"]) and str(identity) == request["volume"], "quarantine_volume_mismatch")
    vault = root / QUARANTINE
    stored = vault / request["lease"]
    receipt = stored.with_suffix(".json")
    restore = request["action"] == "restore"
    if restore:
        private_directory(vault, create=False)
        require(vault.stat().st_dev == device, "quarantine_volume_mismatch")
        original = json.loads(restricted_file(receipt))
        fields(original, ("path", "sha256"), "invalid_quarantine_receipt")
        require(valid_quarantine_path(original["path"]) and matches(SHA256, original["sha256"]),
                "invalid_quarantine_receipt")
        if local:
            request.update(original)
        require(original == {key: request[key] for key in ("path", "sha256")}, "quarantine_receipt_mismatch")
    target = root / request["path"]
    source, destination = (stored, target) if restore else (target, stored)
    require(source.resolve(strict=True) == source, "unsafe_quarantine_path")
    with open_candidate(root, device, source) as (descriptor, metadata):
        require(metadata.st_nlink == 1 and metadata.st_mode & 0o111
                and not metadata.st_mode & (stat.S_ISUID | stat.S_ISGID), "unsafe_quarantine_executable")
        measurement = inspect_descriptor(descriptor)
        require(measurement.get("openedr_executable_format") in ("elf", "script")
                and measurement.get("openedr_executable_sha256") == request["sha256"],
                "quarantine_digest_mismatch")
        if not local:
            approval_age(request)
            consume_approval(request)
        reason = "local_console" if local else None
        audit("authorized", request, reason)
        if not restore:
            private_directory(vault)
            require(vault.stat().st_dev == device, "quarantine_volume_mismatch")
            with ExitStack() as stack:
                os.fsync(open_directory(stack, root))
                try:
                    with receipt.open("x", encoding="utf-8") as stream:
                        json.dump({key: request[key] for key in ("path", "sha256")}, stream)
                        stream.flush()
                        os.fsync(stream.fileno())
                except FileExistsError:
                    raise ValueError("quarantine_receipt_exists") from None
                os.fsync(open_directory(stack, vault))
        move_without_replacing(source, destination, metadata)
    audit("restored" if restore else "quarantined", request, reason)


def serve(local_release, local_restore=None):
    request = None
    audit_ready = False
    os.umask(0o077)
    try:
        private_directory(STATE)
        private_directory(LOG.parent)
        audit_ready = True
        if not local_release and local_restore is None:
            candidate, payload, signature = approval_from_wazuh()
        with (STATE / "lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            if local_release:
                lease, active = owned_table()
                if lease:
                    nft("delete", "table", *TABLE.split())
                audit("local_release", reason="active_lease_removed" if active else "already_inactive")
                return 0
            endpoint, agent, address, port, quarantine_config = load_config(check_enrollment=local_restore is None)
            if local_restore is not None:
                request = {"action": "restore", "lease": local_restore, "agent": agent}
                apply_file_response(request, quarantine_config, local=True)
                return 0
            require((candidate["endpoint"], candidate["agent"]) == (endpoint, agent), "wrong_endpoint")
            verify(candidate, payload, signature)
            request = candidate
            if request["action"] in FILE_ACTIONS:
                apply_file_response(request, quarantine_config)
            else:
                apply(request, address, port)
        return 0
    except (KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        rejected = type(error) is ValueError and re.fullmatch("[a-z_]+", str(error))
        reason = str(error) if rejected else "response_error"
        if audit_ready:
            try:
                audit("rejected" if rejected else "error", request, reason)
            except (OSError, ValueError):
                pass
        print(f"all-os-openedr response: {reason}", file=sys.stderr)
        return 1


def sign(options):
    lease = options.lease
    if options.action in ("isolate", "quarantine") and lease is None:
        lease = uuid.uuid4().hex
    request = {
        "action": options.action, "endpoint": options.endpoint, "agent": options.agent,
        "alert": options.alert, "signer": options.signer, "lease": lease,
        "issued_ms": time.time_ns() // 1_000_000, "seconds": options.seconds,
    }
    if options.action in FILE_ACTIONS:
        request.update(volume=options.volume, path=options.path, sha256=options.sha256)
    elif any(value is not None for value in (options.volume, options.path, options.sha256)):
        raise ValueError("File response fields require quarantine or restore")
    payload = json.dumps(request, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(payload).decode()
    decode_token(f"v1.{encoded}.")
    signature = subprocess.run(
        ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", options.key, "-n", NAMESPACE],
        input=payload, stdout=subprocess.PIPE, check=True,
    ).stdout
    token = f"v1.{encoded}.{base64.urlsafe_b64encode(signature).decode()}"
    label = "Quarantine ID" if options.action in FILE_ACTIONS else "Lease"
    print(f"{label} {lease}", file=sys.stderr)
    print(json.dumps({"command": "!all-os-openedr-response", "arguments": [token]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    options = parser.add_subparsers(dest="operation", required=True)
    options.add_parser("receive")
    options.add_parser("local-release")
    local_restore = options.add_parser("local-restore")
    local_restore.add_argument("--lease", required=True, help="quarantine ID printed by the signer")
    signer = options.add_parser("sign")
    signer.add_argument("action", choices=("isolate", "release", *FILE_ACTIONS))
    signer.add_argument("--endpoint", required=True)
    signer.add_argument("--agent", required=True)
    signer.add_argument("--alert", required=True)
    signer.add_argument("--signer", required=True)
    signer.add_argument("--key", required=True)
    signer.add_argument("--lease")
    signer.add_argument("--seconds", type=int, default=0)
    signer.add_argument("--volume", help="managed ext4 volume UUID for a file response")
    signer.add_argument("--path", help="executable path relative to the managed volume")
    signer.add_argument("--sha256", help="expected executable digest")
    parsed = parser.parse_args()
    if parsed.operation == "sign":
        try:
            sign(parsed)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            parser.error(str(error))
        return 0
    if os.geteuid() != 0:
        parser.error("this operation requires root")
    if parsed.operation == "local-restore" and not matches(ENDPOINT, parsed.lease):
        parser.error("invalid quarantine ID")
    return serve(parsed.operation == "local-release", parsed.lease if parsed.operation == "local-restore" else None)


if __name__ == "__main__":
    raise SystemExit(main())
