"""Exercise IMA appraisal with a fixed approved and unsigned executable pair."""

import errno
import hashlib
import os
import stat
import subprocess
import tempfile
from contextlib import contextmanager

from .apparmor_policy import trusted_file
from .ima_policy import IMA_ATTRIBUTE, IMA_SHA256_PREFIX, approve, open_candidate, select_filesystem


PROBE_DIR = ".openedr-health"
PROBE_BYTES = b"#!/bin/sh\nexit 37\n"
PROBE_DIGEST = hashlib.sha256(PROBE_BYTES).digest()
IMA_RESULTS = frozenset({
    "enforcing", "not_enforced", "approved_probe_failed", "probes_unavailable", "probe_failed",
    "execution_volume_unavailable", "execution_volume_unconfigured", "unknown",
})


@contextmanager
def open_probe(root, device, path):
    if path.resolve(strict=True) != path:
        raise ValueError("The IMA probe must use its canonical path")
    with open_candidate(root, device, path) as (descriptor, metadata):
        if (metadata.st_nlink != 1 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o555
                or os.read(descriptor, len(PROBE_BYTES) + 1) != PROBE_BYTES):
            raise ValueError("The managed IMA probe is invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield descriptor, metadata


def approval_attribute(descriptor):
    try:
        return os.getxattr(descriptor, IMA_ATTRIBUTE)
    except OSError as error:
        if error.errno != errno.ENODATA:
            raise
        return None


def prepare_probes(path):
    root, device, _ = select_filesystem(path)
    directory = root / PROBE_DIR
    directory.mkdir(mode=0o755, exist_ok=True)
    if directory.resolve(strict=True) != directory or directory.stat().st_dev != device:
        raise ValueError("The IMA probe directory must be on the enrolled volume")
    trusted_file(directory)
    for name in ("approved", "unsigned"):
        target = directory / name
        # Link the completed file without replacing anything at the designated path.
        with tempfile.NamedTemporaryFile(dir=directory) as temporary:
            temporary.write(PROBE_BYTES)
            temporary.flush()
            os.fchown(temporary.fileno(), 0, 0)
            os.fchmod(temporary.fileno(), 0o555)
            os.fsync(temporary.fileno())
            try:
                os.link(temporary.name, target, follow_symlinks=False)
            except FileExistsError:
                pass
        with open_probe(root, device, target) as (descriptor, metadata):
            if name == "approved":
                approve(descriptor, metadata, {PROBE_DIGEST.hex(): "trusted"})
                os.fsync(descriptor)
            elif approval_attribute(descriptor) is not None:
                raise ValueError("The unsigned IMA probe has an approval")


def check_ima(root, device):
    directory = root / PROBE_DIR
    try:
        for name, expected in (("approved", IMA_SHA256_PREFIX + PROBE_DIGEST), ("unsigned", None)):
            with open_probe(root, device, directory / name) as (descriptor, _):
                if approval_attribute(descriptor) != expected:
                    return "probes_unavailable"
    except (OSError, ValueError, RuntimeError):
        return "probes_unavailable"
    arguments = {
        "stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
        "env": {"PATH": "/usr/bin"}, "timeout": 3, "check": False,
    }
    try:
        approved = subprocess.run([directory / "approved"], **arguments)
        if approved.returncode != 37:
            return "approved_probe_failed"
    except (OSError, subprocess.SubprocessError):
        return "approved_probe_failed"
    try:
        unsigned = subprocess.run([directory / "unsigned"], **arguments)
    except PermissionError as error:
        return "enforcing" if error.errno == errno.EACCES else "probe_failed"
    except (OSError, subprocess.SubprocessError):
        return "probe_failed"
    return "not_enforced" if unsigned.returncode == 37 else "probe_failed"
