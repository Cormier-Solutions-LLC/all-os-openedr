"""Safely bound local evidence logs shared by Linux sensors."""

import os
import stat
from contextlib import contextmanager


@contextmanager
def exclusive_log(path):
    import fcntl

    metadata = path.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise ValueError("The evidence log requires a root-owned directory")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(path.with_suffix(".lock"), flags, 0o600), "r+b") as lock:
        metadata = os.fstat(lock.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077
                or metadata.st_nlink != 1):
            raise OSError("The evidence log requires a private root-owned lock")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def rotate_evidence(path, added_bytes, limit, backups):
    try:
        metadata = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise OSError("The evidence log must be a regular file with one link")
    if metadata.st_size + added_bytes <= limit:
        return
    for index in range(backups, 0, -1):
        source = path if index == 1 else path.with_name(f"{path.name}.{index - 1}")
        target = path.with_name(f"{path.name}.{index}")
        try:
            source.replace(target)
        except FileNotFoundError:
            continue
