"""Read-only inspection through sudo's own privilege-listing interface."""

import os
import pwd
import re
import shutil
import subprocess

from vulpnix.models import SudoPrivilege, SudoPrivilegeStatus, User
from vulpnix.parsers.sudo import parse_sudo_listing

_COMMAND_TIMEOUT_SECONDS = 5
_SAFE_ACCOUNT_ARGUMENT = re.compile(r"^[^-\s\x00-\x1f\x7f][^\s\x00-\x1f\x7f]*$")


def _not_assessed(account: str, reason: str) -> SudoPrivilege:
    return SudoPrivilege(
        account=account,
        status=SudoPrivilegeStatus.NOT_ASSESSED,
        reason=reason,
    )


def _run_listing(
    sudo_path: str,
    account: str,
    *,
    inspect_other: bool,
) -> SudoPrivilege:
    command = [sudo_path, "-n", "-l"]
    if inspect_other:
        command.extend(("-U", account))

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=_COMMAND_TIMEOUT_SECONDS,
            shell=False,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TERM": "dumb",
                "NO_COLOR": "1",
            },
        )
    except subprocess.TimeoutExpired:
        return _not_assessed(account, "sudo privilege listing timed out")
    except (FileNotFoundError, PermissionError):
        return SudoPrivilege(
            account,
            SudoPrivilegeStatus.UNAVAILABLE,
            reason="sudo executable could not be run",
        )
    except (OSError, UnicodeError):
        return _not_assessed(account, "sudo privilege listing could not be read")

    return parse_sudo_listing(
        account,
        result.stdout or "",
        result.stderr or "",
        result.returncode,
    )


def collect_sudo_privileges(users: tuple[User, ...]) -> tuple[SudoPrivilege, ...]:
    """Inspect the current user and, only as root, other local accounts."""
    effective_uid = os.geteuid()
    try:
        current_account = pwd.getpwuid(effective_uid).pw_name
    except KeyError:
        current_account = None

    accounts = list(dict.fromkeys(user.username for user in users))
    if current_account and current_account not in accounts:
        accounts.insert(0, current_account)

    if not accounts:
        return ()

    trusted_path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    sudo_path = shutil.which("sudo", path=trusted_path)
    if sudo_path is None:
        return tuple(
            SudoPrivilege(
                account,
                SudoPrivilegeStatus.UNAVAILABLE,
                reason="sudo is not installed or not available in standard executable paths",
            )
            for account in accounts
        )

    results: list[SudoPrivilege] = []
    for account in accounts:
        if not _SAFE_ACCOUNT_ARGUMENT.fullmatch(account):
            results.append(_not_assessed(account, "account name cannot be passed safely to sudo"))
        elif current_account is None:
            results.append(_not_assessed(account, "current process account could not be identified"))
        elif account == current_account:
            results.append(_run_listing(sudo_path, account, inspect_other=False))
        elif effective_uid == 0:
            results.append(_run_listing(sudo_path, account, inspect_other=True))
        else:
            results.append(
                _not_assessed(
                    account,
                    "other-account inspection skipped because current process permissions are insufficient",
                )
            )
    return tuple(results)
