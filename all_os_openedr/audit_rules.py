"""Render opt-in Linux Audit rules for Debian execution and configuration monitoring."""

import argparse
import os
import platform
import re
from pathlib import Path


def login_uid(value):
    if not re.fullmatch(r"[0-9]{1,10}", value) or int(value) >= 4294967295:
        raise argparse.ArgumentTypeError("Use a numeric login UID smaller than 4294967295")
    return int(value)


def audit_path(value):
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("Use an absolute path")
    try:
        path = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    if not re.fullmatch(r"/[A-Za-z0-9_./+-]+", str(path)):
        raise argparse.ArgumentTypeError("The resolved path contains unsupported audit rule characters")
    return path


def executable(value):
    path = audit_path(value)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise argparse.ArgumentTypeError("The protected path must be an executable file")
    return path


def config_target(value):
    path = audit_path(value)
    if path.is_dir():
        return "dir", path
    if path.is_file():
        return "path", path
    raise argparse.ArgumentTypeError("The configuration target must be a regular file or directory")


def render_rules(path, approved_uid, session_uid_min=None):
    # Audit uses the first matching rule, so place the narrower detection first.
    for arch in ("b64", "b32"):
        yield (
            f"-a always,exit -F arch={arch} -S execve,execveat -F path={path} "
            f"-F auid!={approved_uid} -F auid!=unset -F success=1 -k openedr-restricted-exec"
        )
        if session_uid_min is not None:
            yield (
                f"-a always,exit -F arch={arch} -S execve,execveat "
                f"-F auid>={session_uid_min} -F auid!=unset -F success=1 -k openedr-session-exec"
            )


def render_config_rules(targets):
    for field, path in dict.fromkeys(targets):
        for arch in ("b64", "b32"):
            yield (
                f"-a always,exit -F arch={arch} -F {field}={path} "
                "-F perm=wa -F success=1 -k openedr-config-change"
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protected-executable", type=executable)
    parser.add_argument("--approved-login-uid", type=login_uid)
    parser.add_argument("--observe-login-execs-from", type=login_uid, metavar="UID")
    parser.add_argument("--watch-config", action="append", type=config_target, default=[], metavar="PATH",
                        help="monitor successful write access and attribute changes on an existing path")
    options = parser.parse_args()
    if (options.protected_executable is None) != (options.approved_login_uid is None):
        parser.error("Use --protected-executable and --approved-login-uid together")
    if options.observe_login_execs_from is not None and options.protected_executable is None:
        parser.error("--observe-login-execs-from requires --protected-executable and --approved-login-uid")
    if options.protected_executable is None and not options.watch_config:
        parser.error("Supply an execution policy or at least one --watch-config path")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("Audit rule generation currently requires Linux amd64")
    if options.protected_executable is not None:
        for rule in render_rules(
            options.protected_executable, options.approved_login_uid, options.observe_login_execs_from
        ):
            print(rule)
    for rule in render_config_rules(options.watch_config):
        print(rule)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
