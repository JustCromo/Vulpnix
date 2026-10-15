"""Parser for Linux /proc/self/mountinfo records."""

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class MountInfo:
    mount_point: str
    options: frozenset[str]
    mount_id: str | None = None
    parent_id: str | None = None
    device_id: str | None = None
    root: str | None = None
    fs_type: str | None = None
    source: str | None = None
    super_options: frozenset[str] = frozenset()


_ESCAPED = re.compile(r"\\([0-7]{3})")


def _unescape_mount_field(value: str) -> str:
    return _ESCAPED.sub(lambda match: chr(int(match.group(1), 8)), value)


def parse_mountinfo(text: str) -> tuple[MountInfo, ...]:
    """Parse mount points and per-mount options, rejecting incomplete input."""
    mounts: list[MountInfo] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError as error:
            raise ValueError(f"mountinfo line {line_number} has no separator") from error
        if len(fields) < 10 or separator < 6 or separator + 3 >= len(fields):
            raise ValueError(f"mountinfo line {line_number} is incomplete")
        mount_point = _unescape_mount_field(fields[4])
        if not mount_point.startswith("/"):
            raise ValueError(f"mountinfo line {line_number} has an invalid mount point")
        options = frozenset(fields[5].split(","))
        if not options or "" in options:
            raise ValueError(f"mountinfo line {line_number} has invalid mount options")
        root = _unescape_mount_field(fields[3])
        fs_type = fields[separator + 1]
        source = _unescape_mount_field(fields[separator + 2])
        super_options = frozenset(fields[separator + 3].split(","))
        if (
            not root.startswith("/")
            or not fs_type
            or not source
            or not super_options
            or "" in super_options
        ):
            raise ValueError(
                f"mountinfo line {line_number} has invalid filesystem metadata"
            )

        mounts.append(
            MountInfo(
                mount_point=mount_point.rstrip("/") or "/",
                options=options,
                mount_id=fields[0],
                parent_id=fields[1],
                device_id=fields[2],
                root=root,
                fs_type=fs_type,
                source=source,
                super_options=super_options,
            )
        )
    if not mounts:
        raise ValueError("mountinfo contains no mount records")
    return tuple(mounts)
