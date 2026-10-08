"""Host information data model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SystemInfo:
    """Descriptive facts about a Linux host, without security conclusions."""

    hostname: str | None = None
    distribution: str | None = None
    distribution_version: str | None = None
    kernel_release: str | None = None
    architecture: str | None = None
    uptime_seconds: float | None = None
