"""Render a standalone Samba share with explicit writer authorization."""

import argparse
import grp
import re
from pathlib import Path


MUTATION_OPERATIONS = "create_file mkdirat renameat unlinkat linkat ftruncate pwrite pwrite_send pwrite_recv"


def share_name(value):
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", value):
        raise argparse.ArgumentTypeError("Use a lowercase share name with letters, digits, hyphens or underscores")
    if value in {"global", "homes", "printers"}:
        raise argparse.ArgumentTypeError("Choose a dedicated share name")
    return value


def export_directory(value):
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("Use an absolute Samba export directory")
    try:
        path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not path.is_dir() or not re.fullmatch(r"/[A-Za-z0-9_./+-]+", str(path)):
        raise argparse.ArgumentTypeError("Use an existing directory below root with a literal Samba path")
    return path


def local_group(value):
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", value):
        raise argparse.ArgumentTypeError("Use a literal local Unix group name")
    try:
        group = grp.getgrnam(value)
    except KeyError as error:
        raise argparse.ArgumentTypeError(f"Group does not exist: {value}") from error
    if group.gr_gid == 0:
        raise argparse.ArgumentTypeError("Use a dedicated non-root group")
    return group


def render_share(name, path, readers, writers):
    if readers.gr_gid == writers.gr_gid:
        raise ValueError("Configure distinct reader and writer groups")
    return "\n".join((
        f"[{name}]",
        f"    path = {path}",
        "    guest ok = no",
        "    read only = yes",
        f"    valid users = @{readers.gr_name} @{writers.gr_name}",
        f"    write list = @{writers.gr_name}",
        "    admin users =",
        "    force user =",
        "    force group =",
        "    follow symlinks = no",
        "    wide links = no",
        "    server smb encrypt = required",
        "    vfs objects = full_audit",
        "    full_audit:prefix = openedr-smb-v1|%S|%I|%u",
        "    full_audit:success = none",
        f"    full_audit:failure = {MUTATION_OPERATIONS}",
        "    full_audit:facility = LOCAL6",
        "    full_audit:priority = NOTICE",
    ))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--share", required=True, type=share_name)
    parser.add_argument("--directory", required=True, type=export_directory)
    parser.add_argument("--readers-group", required=True, type=local_group)
    parser.add_argument("--writers-group", required=True, type=local_group)
    options = parser.parse_args()
    try:
        print(render_share(options.share, options.directory, options.readers_group, options.writers_group))
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
