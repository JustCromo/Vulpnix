"""Verified results from read-only sudo privilege listings."""

from dataclasses import dataclass
from enum import Enum


class SudoPrivilegeStatus(Enum):
    """Outcome of inspecting one account's sudo policy."""

    PRIVILEGES_FOUND = "privileges_found"
    NO_PRIVILEGES = "no_privileges"
    NOT_ASSESSED = "not_assessed"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class SudoGrant:
    """One command grant as reported by sudo, without policy reinterpretation."""

    target_users: tuple[str, ...]
    target_groups: tuple[str, ...] | None
    allowed_commands: tuple[str, ...]
    options: tuple[str, ...]
    source: str | None = None


@dataclass(frozen=True, slots=True)
class SudoPrivilege:
    """The verified or explicitly unavailable result for one account."""

    account: str
    status: SudoPrivilegeStatus
    grants: tuple[SudoGrant, ...] = ()
    host: str | None = None
    reason: str | None = None
    diagnostic: str | None = None
