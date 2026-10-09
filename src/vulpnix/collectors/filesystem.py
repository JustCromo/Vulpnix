"""Collect metadata for a small fixed set of sensitive Linux files."""

import os
import stat
from pathlib import Path

from vulpnix.models import FileMetadataResult, FileMetadataStatus
from vulpnix.parsers.filesystem import normalize_file_metadata

_ETC_DIRECTORY = "/etc"
_SENSITIVE_TARGETS = (
    "passwd",
    "shadow",
    "group",
    "gshadow",
)
_UID_MAP_PATH = Path("/proc/self/uid_map")
_GID_MAP_PATH = Path("/proc/self/gid_map")
_OVERFLOW_UID_PATH = Path("/proc/sys/kernel/overflowuid")
_OVERFLOW_GID_PATH = Path("/proc/sys/kernel/overflowgid")


def _read_id_map(path: Path) -> tuple[tuple[int, int], ...] | None:
    """Read namespace-local ID ranges as (start, length), or return unknown."""
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    ranges: list[tuple[int, int]] = []
    try:
        for line in lines:
            fields = line.split()
            if len(fields) != 3:
                return None
            local_start, _parent_start, length = (int(field, 10) for field in fields)
            if local_start < 0 or length <= 0:
                return None
            ranges.append((local_start, length))
    except ValueError:
        return None
    return tuple(ranges) if ranges else None


def _read_overflow_id(path: Path) -> int | None:
    try:
        value = int(path.read_text(encoding="ascii").strip(), 10)
    except (OSError, UnicodeError, ValueError):
        return None
    return value if value >= 0 else None


def _id_is_mapped(
    identifier: int,
    ranges: tuple[tuple[int, int], ...] | None,
    overflow_id: int | None,
) -> bool:
    return (
        ranges is not None
        and overflow_id is not None
        and identifier != overflow_id
        and any(
        start <= identifier < start + length for start, length in ranges
        )
    )


def _unavailable(path: str, reason: str) -> FileMetadataResult:
    return FileMetadataResult(
        path=path,
        status=FileMetadataStatus.NOT_ASSESSED,
        reason=reason,
    )


def collect_sensitive_file_metadata() -> tuple[FileMetadataResult, ...]:
    """Inspect only fixed /etc entries, without following their final symlink."""
    uid_ranges = _read_id_map(_UID_MAP_PATH)
    gid_ranges = _read_id_map(_GID_MAP_PATH)
    overflow_uid = _read_overflow_id(_OVERFLOW_UID_PATH)
    overflow_gid = _read_overflow_id(_OVERFLOW_GID_PATH)
    full_paths = tuple(f"{_ETC_DIRECTORY}/{name}" for name in _SENSITIVE_TARGETS)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(_ETC_DIRECTORY, flags)
    except FileNotFoundError:
        return tuple(_unavailable(path, "parent directory is missing") for path in full_paths)
    except PermissionError:
        return tuple(_unavailable(path, "permission denied opening parent directory") for path in full_paths)
    except OSError as error:
        reason = f"parent directory could not be opened: {error.strerror or error.__class__.__name__}"
        return tuple(_unavailable(path, reason) for path in full_paths)

    results: list[FileMetadataResult] = []
    try:
        for name, path in zip(_SENSITIVE_TARGETS, full_paths):
            try:
                raw = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                try:
                    raw_uid = raw.st_uid
                    raw_gid = raw.st_gid
                except AttributeError as error:
                    raise ValueError("Incomplete filesystem metadata") from error
                for label, identifier in (("UID", raw_uid), ("GID", raw_gid)):
                    if (
                        isinstance(identifier, bool)
                        or not isinstance(identifier, int)
                        or identifier < 0
                    ):
                        raise ValueError(f"Invalid filesystem {label}")
                metadata = normalize_file_metadata(
                    path,
                    raw,
                    uid_mapped=_id_is_mapped(raw_uid, uid_ranges, overflow_uid),
                    gid_mapped=_id_is_mapped(raw_gid, gid_ranges, overflow_gid),
                )
            except FileNotFoundError:
                results.append(_unavailable(path, "target is missing"))
            except PermissionError:
                results.append(_unavailable(path, "permission denied reading metadata"))
            except (OSError, ValueError) as error:
                reason = error.strerror if isinstance(error, OSError) else str(error)
                results.append(
                    _unavailable(
                        path,
                        f"metadata could not be normalized: {reason or error.__class__.__name__}",
                    )
                )
            else:
                results.append(
                    FileMetadataResult(
                        path=path,
                        status=(
                            FileMetadataStatus.COLLECTED
                            if metadata.uid is not None and metadata.gid is not None
                            else FileMetadataStatus.PARTIAL
                        ),
                        metadata=metadata,
                        reason=(
                            "owner IDs are not mapped in the current user namespace"
                            if metadata.uid is None or metadata.gid is None
                            else None
                        ),
                    )
                )
    finally:
        os.close(directory_fd)
    return tuple(results)
