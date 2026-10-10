"""Helpers for deciding whether kernel owner IDs map to host-visible IDs."""

from pathlib import Path

UID_MAP_PATH = Path("/proc/self/uid_map")
GID_MAP_PATH = Path("/proc/self/gid_map")
OVERFLOW_UID_PATH = Path("/proc/sys/kernel/overflowuid")
OVERFLOW_GID_PATH = Path("/proc/sys/kernel/overflowgid")


def read_id_map(path: Path) -> tuple[tuple[int, int], ...] | None:
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


def read_overflow_id(path: Path) -> int | None:
    try:
        value = int(path.read_text(encoding="ascii").strip(), 10)
    except (OSError, UnicodeError, ValueError):
        return None
    return value if value >= 0 else None


def id_is_mapped(
    identifier: int,
    ranges: tuple[tuple[int, int], ...] | None,
    overflow_id: int | None,
) -> bool:
    return (
        ranges is not None
        and overflow_id is not None
        and identifier != overflow_id
        and any(start <= identifier < start + length for start, length in ranges)
    )
