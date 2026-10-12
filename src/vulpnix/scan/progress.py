from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ScanStage(Enum):
    """High-level stages of a scan."""

    STARTING = "STARTING"
    COLLECTING = "COLLECTING"
    ASSESSING = "ASSESSING"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class ScanProgress:
    """A progress event emitted while a scan is running."""

    stage: ScanStage
    message: str
    completed: int = 0
    total: int | None = None