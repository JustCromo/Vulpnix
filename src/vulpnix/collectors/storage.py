"""Read-only mounted-filesystem and capacity collector for Linux."""

from collections.abc import Callable
import os
from pathlib import Path

from vulpnix.models.storage import (
    MountedFilesystem,
    StorageSnapshot,
    StorageStatus,
)
from vulpnix.parsers.mountinfo import parse_mountinfo


MOUNTINFO_PATH = Path("/proc/self/mountinfo")
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_MOUNTS = 2048


def _metric(value: object) -> int | None:
    """Accept only non-negative integer statvfs fields."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _byte_count(blocks: int | None, block_size: int | None) -> int | None:
    if blocks is None or block_size is None or blocks <= 0 or block_size <= 0:
        return None
    return blocks * block_size


def _inode_count(value: int | None, total: int | None) -> int | None:
    if value is None or total is None or total <= 0 or value > total:
        return None
    return value


def collect_storage_snapshot(
    *,
    mountinfo_text: str | None = None,
    mountinfo_path: Path = MOUNTINFO_PATH,
    statvfs_fn: Callable[[str], object] | None = None,
    max_mounts: int = DEFAULT_MAX_MOUNTS,
) -> StorageSnapshot:
    """Collect mount metadata and capacity without invoking external commands.

    A successful mount inventory does not imply that every filesystem reports
    meaningful capacity or inode counters. Unsupported measurements stay None.
    """
    if (
        isinstance(max_mounts, bool)
        or not isinstance(max_mounts, int)
        or max_mounts < 1
    ):
        raise ValueError("max_mounts must be a positive integer")

    if mountinfo_text is None:
        try:
            raw = mountinfo_path.read_bytes()
        except OSError as error:
            reason = (
                error.strerror
                if isinstance(error, OSError) and error.strerror
                else error.__class__.__name__
            )
            return StorageSnapshot(
                (),
                StorageStatus.NOT_ASSESSED,
                (f"Mount inventory could not be read: {reason}",),
            )

        if len(raw) > MAX_MOUNTINFO_BYTES:
            return StorageSnapshot(
                (),
                StorageStatus.NOT_ASSESSED,
                ("Mount inventory exceeded the configured input size limit.",),
            )
        try:
            mountinfo_text = raw.decode("utf-8")
        except UnicodeError:
            return StorageSnapshot(
                (),
                StorageStatus.NOT_ASSESSED,
                ("Mount inventory was not valid UTF-8.",),
            )

    if len(mountinfo_text.encode("utf-8", errors="replace")) > MAX_MOUNTINFO_BYTES:
        return StorageSnapshot(
            (),
            StorageStatus.NOT_ASSESSED,
            ("Mount inventory exceeded the configured input size limit.",),
        )

    try:
        mounts = parse_mountinfo(mountinfo_text)
    except (UnicodeError, ValueError) as error:
        return StorageSnapshot(
            (),
            StorageStatus.NOT_ASSESSED,
            (f"Mount inventory could not be parsed: {error}",),
        )

    messages: list[str] = []
    limited = len(mounts) > max_mounts
    if limited:
        messages.append(
            f"Mount inventory was limited to {max_mounts} entries; "
            f"{len(mounts) - max_mounts} mount(s) were not inspected."
        )
        mounts = mounts[:max_mounts]

    statvfs = statvfs_fn or os.statvfs
    filesystems: list[MountedFilesystem] = []
    failed_mounts = 0

    for mount in mounts:
        mount_options = tuple(sorted(mount.options))
        super_options = tuple(sorted(mount.super_options))

        try:
            stats = statvfs(mount.mount_point)
        except (OSError, ValueError) as error:
            failed_mounts += 1
            reason = (
                error.strerror
                if isinstance(error, OSError) and error.strerror
                else error.__class__.__name__
            )
            message = (
                f"{mount.mount_point}: capacity metadata unavailable: {reason}"
            )
            messages.append(message)
            filesystems.append(
                MountedFilesystem(
                    mount_point=mount.mount_point,
                    fs_type=mount.fs_type,
                    source=mount.source,
                    mount_options=mount_options,
                    super_options=super_options,
                    total_bytes=None,
                    free_bytes=None,
                    available_bytes=None,
                    total_inodes=None,
                    free_inodes=None,
                    available_inodes=None,
                    status=StorageStatus.NOT_ASSESSED,
                    reason=message,
                )
            )
            continue

        frsize = _metric(getattr(stats, "f_frsize", None))
        bsize = _metric(getattr(stats, "f_bsize", None))
        block_size = frsize if frsize and frsize > 0 else bsize

        blocks = _metric(getattr(stats, "f_blocks", None))
        free_blocks = _metric(getattr(stats, "f_bfree", None))
        available_blocks = _metric(getattr(stats, "f_bavail", None))

        total_bytes = _byte_count(blocks, block_size)
        free_bytes = _byte_count(free_blocks, block_size)
        available_bytes = _byte_count(available_blocks, block_size)

        if total_bytes is not None:
            if free_bytes is not None and free_bytes > total_bytes:
                free_bytes = None
            if available_bytes is not None and available_bytes > total_bytes:
                available_bytes = None
            if (
                available_blocks is not None
                and free_blocks is not None
                and available_blocks > free_blocks
            ):
                available_bytes = None

        total_raw_inodes = _metric(getattr(stats, "f_files", None))
        total_inodes = (
            total_raw_inodes
            if total_raw_inodes is not None and total_raw_inodes > 0
            else None
        )
        free_inodes = _inode_count(
            _metric(getattr(stats, "f_ffree", None)),
            total_inodes,
        )
        available_inodes = _inode_count(
            _metric(getattr(stats, "f_favail", None)),
            total_inodes,
        )
        if (
            free_inodes is not None
            and available_inodes is not None
            and available_inodes > free_inodes
        ):
            available_inodes = None

        filesystems.append(
            MountedFilesystem(
                mount_point=mount.mount_point,
                fs_type=mount.fs_type,
                source=mount.source,
                mount_options=mount_options,
                super_options=super_options,
                total_bytes=total_bytes,
                free_bytes=free_bytes,
                available_bytes=available_bytes,
                total_inodes=total_inodes,
                free_inodes=free_inodes,
                available_inodes=available_inodes,
                status=StorageStatus.COLLECTED,
            )
        )

    status = (
        StorageStatus.PARTIAL
        if limited or failed_mounts
        else StorageStatus.COLLECTED
    )
    return StorageSnapshot(tuple(filesystems), status, tuple(messages))
