"""Local accounts, UID 0 and sudo privileges, expressed through the Area contract.

Collection, parsing and rules are unchanged (``collectors.users``,
``collectors.sudo``, ``parsers``, ``rules.users``). This area keeps the
product's existing judgments:

* an additional UID 0 account is a *review observation*, never a finding
  (``test_additional_uid_zero_accounts_are_reviewed_not_marked_as_findings``);
* a missing privilege is "not verified", never "no privileges";
* anything that could not be read or evaluated is a gap (one per account), so
  coverage is PARTIAL and the area says exactly what is unknown.

Every account is a record; the area-level facts are the verified summaries.
"""

from __future__ import annotations

from collections.abc import Callable
import subprocess

from vulpnix.collectors.sudo import collect_sudo_privileges
from vulpnix.collectors.users import collect_local_users
from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Fact, FindingStatus, Gap, Record
from vulpnix.core.text import display_text
from vulpnix.models import SudoPrivilege, SudoPrivilegeStatus, User
from vulpnix.rules.users import verified_privileged_accounts

_SUDO_CAUSES = {
    "non-interactive listing requires authentication":
        "sudo listing requires authentication",
    "permission denied while inspecting another account":
        "permission denied while inspecting another account",
    "other-account inspection skipped because current process permissions are insufficient":
        "other-account inspection skipped; current process lacks permission",
    "sudo output did not contain a recognized account listing":
        "sudo output format was not recognized",
    "sudo privilege listing timed out": "sudo listing timed out",
    "sudo execution blocked by environment or runtime configuration":
        "environment or sudo runtime configuration blocked inspection",
    "sudo output could not be safely parsed":
        "sudo output was malformed or unsupported",
}
_SUDO_CAUSE_DEFAULT = "sudo privilege state could not be established"
SUDO_UNAVAILABLE_CAUSE = "sudo is unavailable; sudo privileges could not be evaluated"

LOCAL_ACCOUNTS_UNAVAILABLE = "local-accounts-unavailable"
SUDO_COLLECTION_FAILED = "sudo-collection-failed"


def users_error_message(error: Exception) -> str:
    """Explain, in one sentence, why the account database was not usable."""
    if isinstance(error, FileNotFoundError):
        return "The local passwd database could not be found."
    if isinstance(error, PermissionError):
        return "The local passwd database could not be read."
    if isinstance(error, UnicodeError):  # before ValueError: it is a subclass
        return "The local account database contains unreadable text."
    if isinstance(error, ValueError):
        return f"The local account database is malformed: {display_text(str(error))}"
    return "Local account data is unavailable."


def sudo_detail(result: SudoPrivilege | None) -> str:
    """The sudo policy of one account, as sudo reported it."""
    if result is None:
        return "sudo: NOT_ASSESSED"
    if result.grants:
        grant_details = tuple(
            f"runas={','.join(grant.target_users)}"
            + (
                f":{','.join(grant.target_groups)}"
                if grant.target_groups is not None
                else ""
            )
            + " "
            f"commands={','.join(grant.allowed_commands)}"
            + (f" options={','.join(grant.options)}" if grant.options else "")
            + (f" source={grant.source}" if grant.source else "")
            for grant in result.grants
        )
        context = f" host={result.host}" if result.host else ""
        return "sudo:" + context + " " + "; ".join(grant_details)
    detail = result.status.value
    if result.reason:
        detail += f" ({result.reason})"
    return f"sudo: {detail}"


def _sudo_gap(result: SudoPrivilege) -> Gap | None:
    if result.status is SudoPrivilegeStatus.UNAVAILABLE:
        return Gap(
            f"sudo_unavailable:{result.account}",
            f"{result.account}: {SUDO_UNAVAILABLE_CAUSE}",
            subject=result.account,
            cause=SUDO_UNAVAILABLE_CAUSE,
        )
    if result.status is SudoPrivilegeStatus.NOT_ASSESSED:
        cause = _SUDO_CAUSES.get(result.reason, _SUDO_CAUSE_DEFAULT)
        return Gap(
            f"sudo_not_assessed:{result.account}",
            f"{result.account}: {cause}",
            subject=result.account,
            cause=cause,
        )
    return None


def _account_gap(user: User) -> Gap | None:
    missing = []
    if user.account_state is None:
        missing.append("account state")
    if user.groups is None:
        missing.append("group membership")
    if not missing:
        return None
    cause = " and ".join(missing) + " unavailable"
    return Gap(
        f"account_incomplete:{user.username}",
        f"{user.username}: {cause}",
        subject=user.username,
        cause=cause,
    )


class UsersArea:
    """Local accounts, UID 0 accounts and verified sudo privileges."""

    id = "users"
    title = "USERS"
    description = "User and privilege assessment"

    def __init__(
        self,
        users_collector: Callable[[], tuple[User, ...]] | None = None,
        sudo_collector: Callable[[tuple[User, ...]], tuple[SudoPrivilege, ...]] | None = None,
    ) -> None:
        # ``None`` resolves collectors at run time so tests can patch them.
        self._users_collector = users_collector
        self._sudo_collector = sudo_collector

    def run(self, ctx: ExecutionContext) -> AreaResult:
        users_collector = self._users_collector or collect_local_users
        sudo_collector = self._sudo_collector or collect_sudo_privileges
        try:
            users = users_collector()
        except (OSError, UnicodeError, ValueError) as error:
            return AreaResult(
                area_id=self.id,
                title=self.title,
                status=AreaStatus.NOT_ASSESSED,
                gaps=(Gap(LOCAL_ACCOUNTS_UNAVAILABLE, users_error_message(error)),),
            )

        gaps: list[Gap] = []
        try:
            sudo_privileges = sudo_collector(users)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
            # Accounts are known; privileges are not. Say so instead of dropping both.
            sudo_privileges = ()
            gaps.append(
                Gap(
                    SUDO_COLLECTION_FAILED,
                    f"sudo privileges could not be collected: {display_text(str(error))}",
                )
            )

        sudo_by_account = {result.account: result for result in sudo_privileges}
        privileged = verified_privileged_accounts(users, sudo_privileges)
        sudo_accounts = tuple(
            result.account
            for result in sudo_privileges
            if result.status is SudoPrivilegeStatus.PRIVILEGES_FOUND and result.grants
        )
        sudo_without = tuple(
            result.account
            for result in sudo_privileges
            if result.status is SudoPrivilegeStatus.NO_PRIVILEGES
        )
        uid_zero = tuple(user.username for user in users if user.uid == 0)
        additional_uid_zero = tuple(name for name in uid_zero if name != "root")

        if not uid_zero:
            uid_zero_status = None
        elif additional_uid_zero:
            uid_zero_status = FindingStatus.REVIEW
        else:
            uid_zero_status = FindingStatus.PASS

        def privileged_state(user: User) -> bool | None:
            if user.uid == 0 or user.username in privileged:
                return True
            sudo_result = sudo_by_account.get(user.username)
            if user.privileged is False or (
                sudo_result is not None
                and sudo_result.status is SudoPrivilegeStatus.NO_PRIVILEGES
            ):
                return False
            return None

        records = tuple(
            Record(
                kind="account",
                key=user.username,
                label=user.username,
                fields=(
                    ("uid", user.uid),
                    ("gid", user.gid),
                    ("groups", user.groups),
                    ("shell", user.shell),
                    ("privileged", privileged_state(user)),
                    ("account_state", user.account_state),
                    ("sudo", sudo_detail(sudo_by_account.get(user.username))),
                ),
            )
            for user in users
        )

        def names(values: tuple[str, ...]) -> str:
            return ", ".join(values) or "none"

        facts = (
            Fact("local_accounts", "Local accounts", str(len(users)), raw=len(users)),
            Fact("uid0_accounts", "UID 0 accounts", names(uid_zero), uid_zero_status, raw=uid_zero),
            Fact("privileged_accounts", "Privileged accounts", names(privileged), raw=privileged),
            Fact("sudo_accounts", "Sudo access", names(sudo_accounts), raw=sudo_accounts),
            Fact(
                "sudo_no_privileges",
                "Inspected accounts without sudo access",
                names(sudo_without),
                raw=sudo_without,
            ),
        )

        gaps.extend(gap for user in users if (gap := _account_gap(user)) is not None)
        gaps.extend(gap for result in sudo_privileges if (gap := _sudo_gap(result)) is not None)
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=AreaStatus.PARTIAL if gaps else AreaStatus.COMPLETE,
            facts=facts,
            records=records,
            gaps=tuple(gaps),
        )
