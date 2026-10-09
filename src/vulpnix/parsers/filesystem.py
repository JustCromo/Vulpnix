"""Normalize OS filesystem metadata without reading file contents."""

import stat
from typing import Protocol

from vulpnix.models import FileMetadata


class _StatLike(Protocol):
    st_uid: int
    st_gid: int
    st_mode: int
    st_size: int


def normalize_file_metadata(
    path: str,
    raw: _StatLike,
    *,
    uid_mapped: bool = True,
    gid_mapped: bool = True,
) -> FileMetadata:
    """Validate and normalize an lstat/stat-result for a fixed target."""
    try:
        raw_mode = raw.st_mode
        raw_uid = raw.st_uid
        raw_gid = raw.st_gid
        raw_size = raw.st_size
    except AttributeError as error:
        raise ValueError("Incomplete filesystem metadata") from error
    if isinstance(raw_mode, bool) or not isinstance(raw_mode, int) or raw_mode < 0:
        raise ValueError("Invalid filesystem type/mode")
    numeric_fields = {
        "UID": raw_uid,
        "GID": raw_gid,
        "mode": stat.S_IMODE(raw_mode),
        "size": raw_size,
    }
    for name, value in numeric_fields.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"Invalid filesystem {name}")
    mode = numeric_fields["mode"]
    if mode > 0o7777:
        raise ValueError("Invalid filesystem mode")

    if stat.S_ISREG(raw_mode):
        file_type = "regular file"
    elif stat.S_ISDIR(raw_mode):
        file_type = "directory"
    elif stat.S_ISLNK(raw_mode):
        file_type = "symlink"
    else:
        file_type = "other"

    return FileMetadata(
        path=path,
        uid=numeric_fields["UID"] if uid_mapped else None,
        gid=numeric_fields["GID"] if gid_mapped else None,
        mode=mode,
        size=numeric_fields["size"],
        type=file_type,
    )
