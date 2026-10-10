"""Normalized results and coverage for bounded set-ID file discovery."""

from dataclasses import dataclass
from enum import Enum

from vulpnix.models.file_metadata import FileMetadata


class CoverageStatus(Enum):
    COLLECTED = "COLLECTED"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class SetIdFile:
    """Metadata and minimal ELF/mount context for a discovered set-ID file."""

    metadata: FileMetadata
    is_elf: bool | None
    mount_options: tuple[str, ...] | None
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class FilesystemCoverage:
    """Bounded discovery result, including incomplete-coverage explanations."""

    files: tuple[SetIdFile, ...]
    status: CoverageStatus
    roots: tuple[str, ...]
    entries_examined: int
    elapsed_seconds: float
    review: tuple[str, ...] = ()
