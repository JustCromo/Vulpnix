"""Normalized metadata for fixed sensitive filesystem targets."""

from dataclasses import dataclass
from enum import Enum


class FileMetadataStatus(Enum):
    """Whether metadata for a target was collected reliably."""

    COLLECTED = "collected"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"


@dataclass(frozen=True, slots=True)
class FileMetadata:
    """Metadata from one filesystem entry; IDs are numeric and authoritative."""

    path: str
    uid: int | None
    gid: int | None
    mode: int
    size: int
    type: str


@dataclass(frozen=True, slots=True)
class FileMetadataResult:
    """A collected metadata record or an explicit reason it is unavailable."""

    path: str
    status: FileMetadataStatus
    metadata: FileMetadata | None = None
    reason: str | None = None
