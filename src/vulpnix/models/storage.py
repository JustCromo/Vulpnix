"""Normalized storage and mounted-filesystem observations."""

from dataclasses import dataclass
from enum import Enum


class StorageStatus(Enum):
    COLLECTED = "COLLECTED"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class MountedFilesystem:
    """One mount record and its best-effort statvfs measurements."""

    mount_point: str
    fs_type: str | None
    source: str | None
    mount_options: tuple[str, ...]
    super_options: tuple[str, ...]
    total_bytes: int | None
    free_bytes: int | None
    available_bytes: int | None
    total_inodes: int | None
    free_inodes: int | None
    available_inodes: int | None
    status: StorageStatus
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class StorageSnapshot:
    """Mounted-filesystem inventory and coverage state."""

    filesystems: tuple[MountedFilesystem, ...]
    status: StorageStatus
    messages: tuple[str, ...] = ()
