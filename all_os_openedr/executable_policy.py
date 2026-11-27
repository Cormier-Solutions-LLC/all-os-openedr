"""Apply a signed executable verdict catalog to the enrolled Debian endpoint."""

import argparse
import fcntl
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .apparmor_policy import trusted_file
from .executable import MAX_CATALOG_SIZE, POLICY_TARGET, file_version, parse_catalog, read_catalog_record, unique_fields
from .response import restricted_file, verify_ssh_signature


CONFIG = Path("/etc/all-os-openedr/executable-policy.json")
SIGNERS = CONFIG.with_name("executable-policy-signers")
CATALOG = Path("/etc/all-os-openedr-executable-verdicts.json")
LOG = Path("/var/log/all-os-openedr-policy/changes.jsonl")
NAMESPACE = "all-os-openedr-executable-policy-v1"
MAX_SIGNATURE = 16 * 1024


class Rejected(ValueError):
    pass


def protected_directory(path):
    trusted_file(path)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise OSError("Expected a root-owned directory")


def local_target():
    enrollment = json.loads(restricted_file(CONFIG), object_pairs_hook=unique_fields)
    if (not isinstance(enrollment, dict) or set(enrollment) != {"schema", "target"}
            or type(enrollment["schema"]) is not int or enrollment["schema"] != 1
            or not isinstance(enrollment["target"], str) or not POLICY_TARGET.fullmatch(enrollment["target"])):
        raise Rejected("invalid_enrollment")
    return enrollment["target"]


def read_input(path, limit):
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
            raise Rejected("invalid_input_file")
        data = stream.read(limit + 1)
        if len(data) != metadata.st_size or file_version(metadata) != file_version(os.fstat(stream.fileno())):
            raise Rejected("input_changed_while_reading")
    return data


def current_catalog(target):
    try:
        digest, catalog = read_catalog_record(CATALOG)
    except FileNotFoundError:
        return None, {"revision": 0}
    except (OSError, ValueError, RecursionError) as error:
        raise Rejected("active_catalog_invalid") from error
    if catalog.get("target", target) != target:
        raise Rejected("active_catalog_target_mismatch")
    return digest, catalog


def update_catalog(payload):
    with tempfile.NamedTemporaryFile(dir=CATALOG.parent, delete=False) as temporary:
        path = Path(temporary.name)
        try:
            temporary.write(payload)
            temporary.flush()
            os.fchmod(temporary.fileno(), 0o644)
            os.fsync(temporary.fileno())
            path.replace(CATALOG)
        finally:
            path.unlink(missing_ok=True)


def policy_event(result, target=None, catalog=None, digest=None, reason=None):
    event = {
        "openedr_source": "all-os-openedr",
        "openedr_schema": 1,
        "openedr_event": "endpoint.executable_policy",
        "openedr_event_id": uuid.uuid4().hex,
        "openedr_host": socket.gethostname(),
        "openedr_observed_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "openedr_policy_result": result,
    }
    if target is not None:
        event["openedr_policy_target"] = target
    if digest is not None:
        event["openedr_executable_catalog_sha256"] = digest
    if catalog is not None:
        event["openedr_policy_revision"] = catalog.get("revision", 0)
        if "signer" in catalog:
            event["openedr_policy_signer"] = catalog["signer"]
    if reason is not None:
        event["openedr_policy_reason"] = reason
    return event


def open_log():
    protected_directory(LOG.parent.parent)
    LOG.parent.mkdir(mode=0o750, exist_ok=True)
    protected_directory(LOG.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    log = os.fdopen(os.open(LOG, flags, 0o640), "ab")
    metadata = os.fstat(log.fileno())
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        log.close()
        raise OSError("Expected a root-owned regular audit file")
    return log


def emit(event, log=None):
    line = json.dumps(event, separators=(",", ":"))
    if log is not None:
        data = (line + "\n").encode()
        if os.write(log.fileno(), data) != len(data):
            raise OSError("Incomplete audit write")
        os.fsync(log.fileno())
    print(line)


def apply(payload_path, signature_path, log):
    lock_path = CONFIG.with_name("executable-policy.lock")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(lock_path, flags, 0o600), "r+b") as lock:
        metadata = os.fstat(lock.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077
                or metadata.st_nlink != 1):
            raise OSError("Expected a private root-owned policy lock")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        target = local_target()
        digest, verified = None, None
        try:
            payload = read_input(payload_path, MAX_CATALOG_SIZE)
            signature = read_input(signature_path, MAX_SIGNATURE)
            try:
                catalog = parse_catalog(payload)
            except (ValueError, RecursionError) as error:
                raise Rejected("invalid_catalog") from error
            if catalog["schema"] != 2:
                raise Rejected("unsigned_catalog_schema")
            keys = restricted_file(SIGNERS)
            if not verify_ssh_signature(keys, catalog["signer"], NAMESPACE, payload, signature, CONFIG.parent):
                raise Rejected("bad_signature")
            verified = catalog
            digest = hashlib.sha256(payload).hexdigest()
            if catalog["target"] != target:
                raise Rejected("wrong_target")
            _, active = current_catalog(target)
            if catalog["revision"] <= active.get("revision", 0):
                raise Rejected("stale_or_replayed_revision")
        except Rejected as error:
            emit(policy_event("rejected", target, verified, digest, str(error)), log)
            return 1
        directory_fd = os.open(CATALOG.parent, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        try:
            update_catalog(payload)
            try:
                os.fsync(directory_fd)
            except OSError:
                emit(policy_event("applied", target, catalog, digest, "catalog_directory_sync_failed"), log)
                return 2
            try:
                emit(policy_event("applied", target, catalog, digest), log)
            except OSError:
                print("Policy is active. Run status --record to recover its receipt.", file=sys.stderr)
                return 2
        finally:
            os.close(directory_fd)
        return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    install = commands.add_parser("apply", help="Verify and install a more recent catalog revision")
    install.add_argument("catalog", type=Path)
    install.add_argument("signature", type=Path)
    status = commands.add_parser("status", help="Report the active catalog revision and digest")
    status.add_argument("--record", action="store_true", help="Write the current state to the audit log")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Executable policy administration requires root")
    try:
        protected_directory(CONFIG.parent)
        protected_directory(CATALOG.parent)
        if args.action == "apply":
            with open_log() as log:
                return apply(args.catalog, args.signature, log)
        target = local_target()
        digest, catalog = current_catalog(target)
        event = policy_event("current", target, catalog, digest)
        if args.record:
            with open_log() as log:
                emit(event, log)
        else:
            emit(event)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    return 0
