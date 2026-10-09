"""Normalized facts about a local account."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class User:
    """Account facts, with unknown privilege/state kept explicit."""

    username: str
    uid: int
    gid: int
    groups: tuple[str, ...] | None
    shell: str | None
    privileged: bool | None
    account_state: str | None = None
