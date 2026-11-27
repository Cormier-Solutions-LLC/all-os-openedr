"""Prepare kernel IMA appraisal for an operator-selected Debian execution volume."""

import argparse
import errno
import hashlib
import json
import os
import platform
import stat
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path

from .apparmor_policy import trusted_file
from .executable import file_version, read_catalog


IMA_ATTRIBUTE = "security.ima"
IMA_SHA256_PREFIX = bytes((4, 4))  # IMA digest-ng format and Linux HASH_ALGO_SHA256.


def device_number(dev):
    return f"{os.major(dev)}:{os.minor(dev)}"


def select_filesystem(path):
    root = Path(path).resolve(strict=True)
    metadata = root.stat()
    if not stat.S_ISDIR(metadata.st_mode) or not root.is_mount() or metadata.st_dev == Path("/").stat().st_dev:
        raise ValueError("Select a dedicated mounted filesystem separate from the system root")
    trusted_file(root)
    result = subprocess.run(
        ["/usr/bin/findmnt", "--list", "--json", "--output", "TARGET,FSTYPE,UUID,MAJ:MIN"],
        check=True, capture_output=True, text=True, timeout=10,
    )
    mounts = json.loads(result.stdout)["filesystems"]
    device = device_number(metadata.st_dev)
    match = next((mount for mount in mounts if mount["target"] == str(root) and mount["maj:min"] == device), None)
    if match is None or match["fstype"] != "ext4" or not match["uuid"]:
        raise ValueError("Select the mount root of an ext4 filesystem with a visible UUID")
    identity = uuid.UUID(match["uuid"])
    if not identity.int or any(mount["uuid"] == str(identity) and mount["maj:min"] != device for mount in mounts):
        raise ValueError("The execution volume must have a unique nonzero UUID")
    return root, metadata.st_dev, identity


def policy_rules(identity, launcher_uid=None, *, appraise_uids=()):
    if launcher_uid is not None and not 0 < launcher_uid < 0xFFFFFFFF:
        raise ValueError("Choose a non-root launcher UID between 1 and 4294967294")
    appraise_uids = tuple(appraise_uids)
    if any(type(uid) is not int or not 0 < uid < 0xFFFFFFFF for uid in appraise_uids):
        raise ValueError("Choose non-root appraisal UIDs between 1 and 4294967294")
    if launcher_uid in appraise_uids:
        raise ValueError("Use a separate UID for the containment launcher")
    if identity is None:
        if launcher_uid is not None:
            raise ValueError("A launcher read exception requires a managed execution volume")
        if not appraise_uids:
            raise ValueError("Select an execution volume or one or more appraisal UIDs")
    else:
        yield f"appraise func=BPRM_CHECK fsuuid={identity}"
        yield f"appraise func=MMAP_CHECK mask=MAY_EXEC fsuuid={identity}"
    if launcher_uid is not None:
        read_rule = f"func=FILE_CHECK mask=^MAY_READ fsuuid={identity}"
        yield f"dont_appraise {read_rule} uid={launcher_uid}"
        yield f"appraise {read_rule} uid>0"
    for uid in sorted(set(appraise_uids)):
        for credential in ("uid", "euid"):
            scope = f"{credential}={uid} fowner>0 appraise_type=imasig"
            yield f"appraise func=BPRM_CHECK {scope}"
            yield f"appraise func=CREDS_CHECK {scope}"
            yield f"appraise func=MMAP_CHECK mask=MAY_EXEC {scope}"


@contextmanager
def open_candidate(root, device, value):
    path = Path(value).resolve(strict=True)
    if not path.is_relative_to(root):
        raise ValueError("Select a file below the chosen mount root")
    trusted_file(path)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_dev != device
                or metadata.st_uid != 0 or metadata.st_mode & 0o022):
            raise ValueError("Approval requires a root-owned regular file on the selected filesystem")
        yield fd, metadata
    finally:
        os.close(fd)


def approve(fd, metadata, verdicts):
    digest = hashlib.sha256()
    while block := os.read(fd, 128 * 1024):
        digest.update(block)
    if file_version(metadata) != file_version(os.fstat(fd)):
        raise ValueError("The file changed during approval")
    fingerprint = digest.hexdigest()
    if verdicts.get(fingerprint) != "trusted":
        raise ValueError("The file's SHA-256 requires a trusted entry in the local catalog")
    value = IMA_SHA256_PREFIX + digest.digest()
    try:
        os.setxattr(fd, IMA_ATTRIBUTE, value, os.XATTR_CREATE)
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise
        if os.getxattr(fd, IMA_ATTRIBUTE) != value:
            raise ValueError("An IMA attribute already exists for a different approval") from error
    return fingerprint


def revoke(fd):
    try:
        value = os.getxattr(fd, IMA_ATTRIBUTE)
    except OSError as error:
        if error.errno == errno.ENODATA:
            return
        raise
    if len(value) != 34 or not value.startswith(IMA_SHA256_PREFIX):
        raise ValueError("The existing IMA attribute uses a different approval format")
    os.removexattr(fd, IMA_ATTRIBUTE)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("policy", "approve", "revoke"):
        command = commands.add_parser(name)
        command.add_argument("--filesystem", required=name != "policy", metavar="MOUNT_ROOT")
        if name == "policy":
            command.add_argument("--launcher-uid", type=int, metavar="UID",
                                 help="appraise non-root file reads except for this dedicated containment service UID")
            command.add_argument("--appraise-user", type=int, action="append", default=[], metavar="UID",
                                 help="require IMA signatures for non-root-owned code run by this UID outside the volume")
        if name in ("approve", "revoke"):
            command.add_argument("file")
        if name == "approve":
            command.add_argument("--catalog", required=True)
    options = parser.parse_args()
    if platform.system() != "Linux" or os.geteuid() != 0:
        parser.error("Run this command as root on Linux")
    try:
        if options.command == "policy":
            identity = select_filesystem(options.filesystem)[2] if options.filesystem is not None else None
            print(*policy_rules(identity, options.launcher_uid, appraise_uids=options.appraise_user), sep="\n")
            return 0
        root, device, _ = select_filesystem(options.filesystem)
        with open_candidate(root, device, options.file) as (fd, metadata):
            if options.command == "approve":
                catalog_id, verdicts = read_catalog(options.catalog)
                if catalog_id is None:
                    raise ValueError("Supply a valid root-owned executable verdict catalog")
                print(approve(fd, metadata, verdicts))
            else:
                revoke(fd)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"all-os-openedr-ima: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
