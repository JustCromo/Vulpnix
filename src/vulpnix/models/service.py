"""Service data model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Service:
    """Observed service facts without a security judgment."""

    name: str
    state: str | None = None
    enabled: bool | None = None
    pid: int | None = None
    source: str = "systemd"
    unit_file_state: str | None = None
