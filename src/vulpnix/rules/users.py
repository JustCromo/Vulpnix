"""Privilege facts derived from normalized account and sudo data."""

from vulpnix.models import SudoPrivilege, SudoPrivilegeStatus, User


def verified_privileged_accounts(
    users: tuple[User, ...],
    sudo_privileges: tuple[SudoPrivilege, ...],
) -> tuple[str, ...]:
    """Return accounts with verified UID 0 or sudo command access."""
    sudo_accounts = {
        result.account
        for result in sudo_privileges
        if result.status is SudoPrivilegeStatus.PRIVILEGES_FOUND and result.grants
    }
    return tuple(
        user.username
        for user in users
        if user.privileged is True or user.username in sudo_accounts
    )
