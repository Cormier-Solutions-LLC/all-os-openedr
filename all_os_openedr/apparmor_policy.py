"""Render a Debian AppArmor allowlist for a managed workload."""

import argparse
import os
import platform
import re
from functools import partial
from pathlib import Path


def profile_name(value):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", value):
        raise argparse.ArgumentTypeError("Use 1 to 48 lowercase letters, digits or hyphens")
    return f"all-os-openedr-{value}"


def policy_path(value, *, directory=False):
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("Use an absolute path")
    try:
        path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", str(path)):
        raise argparse.ArgumentTypeError(f"Use a literal AppArmor path below the root directory: {path}")
    if directory and not path.is_dir():
        raise argparse.ArgumentTypeError(f"Use an existing directory: {path}")
    if not directory and not path.is_file():
        raise argparse.ArgumentTypeError(f"Use an existing regular file: {path}")
    return path


def trusted_file(path):
    for component in (path, *path.parents):
        metadata = component.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError(f"Approved code requires root ownership and root-only write access: {component}")


def render_profile(name, executables, libraries, reads, writes, protected_trees=(), write_directories=()):
    code_files = (*executables, *libraries)
    for path in executables:
        if not os.access(path, os.X_OK):
            raise ValueError(f"Approved executable lacks execute permission: {path}")
    for path in code_files:
        trusted_file(path)
    for path in writes:
        if any(path.samefile(code) for code in code_files):
            raise ValueError(f"An approved code file cannot also be writable: {path}")
        if any(path.is_relative_to(tree) for tree in protected_trees):
            raise ValueError(f"Writable file is inside a protected tree: {path}")
    for directory in write_directories:
        if any(code.parent == directory for code in code_files):
            raise ValueError(f"Writable directory contains approved code: {directory}")
        if any(tree.is_relative_to(directory) or directory.is_relative_to(tree) for tree in protected_trees):
            raise ValueError(f"Writable directory overlaps a protected tree: {directory}")

    lines = [
        "abi <abi/4.0>,",
        "",
        f"profile {name} {{",
        "  signal (receive) set=(hup, int, quit, abrt, kill, term, cont) peer=unconfined,",
        f"  signal (send, receive) peer={name},",
    ]
    for paths, permissions in (
        (executables, "rix"),
        (libraries, "mr"),
        (reads, "r"),
        (writes, "rw"),
    ):
        lines.extend(f'  "{path}" {permissions},' for path in sorted(set(paths)))
    for path in sorted(set(protected_trees)):
        for suffix in ("/", "/**"):
            lines.append(f'  "{path}{suffix}" r,')
            lines.append(f'  audit deny "{path}{suffix}" wl,')
            lines.append(f'  audit deny "{path}{suffix}" a,')
    for path in sorted(set(write_directories)):
        lines.append(f'  "{path}/" r,')
        lines.append(f'  "{path}/*" rw,')
    lines.append("}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, type=profile_name)
    parser.add_argument("--allow-executable", action="append", required=True, type=policy_path)
    for option in ("--allow-library", "--read-file", "--write-file"):
        parser.add_argument(option, action="append", default=[], type=policy_path)
    directory_path = partial(policy_path, directory=True)
    parser.add_argument("--protect-tree", action="append", default=[], type=directory_path,
                        help="allow reading a directory tree and audit denied writes and hard links")
    parser.add_argument("--write-directory", action="append", default=[], type=directory_path,
                        help="allow writes to files directly in an approved output directory")
    options = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("AppArmor profile generation requires Linux")
    try:
        print(render_profile(
            options.name, options.allow_executable, options.allow_library,
            options.read_file, options.write_file, options.protect_tree, options.write_directory,
        ))
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
