"""Bounded, no-follow discovery of Linux SUID/SGID regular files."""

from collections.abc import Callable
import os
from pathlib import Path
import stat
import time

from vulpnix.collectors.id_mapping import (
    GID_MAP_PATH,
    OVERFLOW_GID_PATH,
    OVERFLOW_UID_PATH,
    UID_MAP_PATH,
    id_is_mapped,
    read_id_map,
    read_overflow_id,
)
from vulpnix.models import CoverageStatus, FilesystemCoverage, FileMetadata, SetIdFile
from vulpnix.parsers.filesystem import normalize_file_metadata
from vulpnix.parsers.mountinfo import MountInfo, parse_mountinfo

DEFAULT_ROOTS = ("/usr", "/opt", "/bin", "/sbin")
DEFAULT_ENTRY_BUDGET = 250_000
DEFAULT_TIME_BUDGET_SECONDS = 10.0
MOUNTINFO_PATH = Path("/proc/self/mountinfo")


def _snapshot(raw: os.stat_result) -> tuple[int, ...]:
    return (
        raw.st_dev,
        raw.st_ino,
        raw.st_mode,
        raw.st_uid,
        raw.st_gid,
        raw.st_size,
        raw.st_mtime_ns,
        raw.st_ctime_ns,
    )


def _mount_for_path(path: str, mounts: tuple[MountInfo, ...]) -> MountInfo | None:
    candidates = [
        mount
        for mount in mounts
        if path == mount.mount_point
        or path.startswith(mount.mount_point.rstrip("/") + "/")
    ]
    if not candidates:
        return None
    longest = max(len(mount.mount_point) for mount in candidates)
    selected = tuple(mount for mount in candidates if len(mount.mount_point) == longest)
    options = frozenset(option for mount in selected for option in mount.options)
    return MountInfo(selected[0].mount_point, options)


def _open_directory_beneath_root(
    root: str,
    root_stat: os.stat_result,
    path: str,
    expected_stat: os.stat_result,
) -> int:
    """Open each path component relative to a no-follow directory descriptor."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(root, flags)
    try:
        opened = os.fstat(descriptor)
        if opened.st_dev != root_stat.st_dev or opened.st_ino != root_stat.st_ino:
            raise OSError("scan root changed during traversal")
        relative = os.path.relpath(path, root)
        if relative != ".":
            for component in relative.split(os.sep):
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != expected_stat.st_dev
            or opened.st_ino != expected_stat.st_ino
        ):
            raise OSError("directory changed during traversal")
        result = descriptor
        descriptor = -1
        return result
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _inspect_elf_signature(
    parent_fd: int,
    name: str,
    discovered: os.stat_result,
) -> tuple[bool | None, str | None]:
    """Read a bounded ELF identification/header prefix and verify stability."""
    if not hasattr(os, "O_NOFOLLOW"):
        return None, "no-follow file opening is unavailable"
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        return None, f"file could not be opened safely: {error.strerror or error.__class__.__name__}"
    try:
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or _snapshot(before) != _snapshot(discovered):
                return None, "file changed between discovery and signature inspection"
            header = os.read(descriptor, 24)
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError:
            return None, "file changed or became unavailable during signature inspection"
        if (
            _snapshot(before) != _snapshot(after)
            or _snapshot(before) != _snapshot(current)
        ):
            return None, "file changed between discovery and signature inspection"
        if len(header) < 24:
            return None, "file signature is incomplete"
        if header[:4] != b"\x7fELF":
            return False, None
        elf_class, byte_order = header[4], header[5]
        if elf_class not in {1, 2} or byte_order not in {1, 2} or header[6] != 1:
            return None, "ELF identification header is malformed"
        byteorder = "little" if byte_order == 1 else "big"
        elf_type = int.from_bytes(header[16:18], byteorder)
        version = int.from_bytes(header[20:24], byteorder)
        if version != 1 or elf_type not in {1, 2, 3, 4}:
            return None, "ELF header is malformed"
        return elf_type in {2, 3}, None
    finally:
        os.close(descriptor)


def _read_mounts(
    mountinfo_text: str | None,
    mountinfo_path: Path,
) -> tuple[MountInfo, ...]:
    if mountinfo_text is None:
        mountinfo_text = mountinfo_path.read_text(encoding="utf-8")
    return parse_mountinfo(mountinfo_text)


def collect_setid_files(
    *,
    roots: tuple[str, ...] = DEFAULT_ROOTS,
    mountinfo_text: str | None = None,
    mountinfo_path: Path = MOUNTINFO_PATH,
    max_entries: int = DEFAULT_ENTRY_BUDGET,
    max_seconds: float = DEFAULT_TIME_BUDGET_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> FilesystemCoverage:
    """Discover set-ID files under a bounded set of roots and time/entry budget.

    Nested mount points are not descended into. Configured roots that are
    themselves mount points are scanned, with their own mount options applied.
    """
    normalized_roots = tuple(os.path.abspath(root) for root in roots)
    start = clock()
    try:
        mounts = _read_mounts(mountinfo_text, mountinfo_path)
    except (OSError, UnicodeError, ValueError) as error:
        reason = f"mount boundaries could not be established: {error}"
        return FilesystemCoverage(
            (), CoverageStatus.NOT_ASSESSED, normalized_roots, 0,
            max(0.0, clock() - start), (reason,),
        )

    uid_ranges = read_id_map(UID_MAP_PATH)
    gid_ranges = read_id_map(GID_MAP_PATH)
    overflow_uid = read_overflow_id(OVERFLOW_UID_PATH)
    overflow_gid = read_overflow_id(OVERFLOW_GID_PATH)
    if not all((uid_ranges, gid_ranges, overflow_uid is not None, overflow_gid is not None)):
        id_mapping_reason = "owner ID mapping could not be verified in the current namespace"
    else:
        id_mapping_reason = None

    files: list[SetIdFile] = []
    review: list[str] = []
    entries_examined = 0
    partial = False
    stopped = False
    nofollow_available = hasattr(os, "O_NOFOLLOW")
    if not nofollow_available:
        return FilesystemCoverage(
            (), CoverageStatus.NOT_ASSESSED, normalized_roots, 0,
            max(0.0, clock() - start),
            ("no-follow filesystem operations are unavailable",),
        )

    def budget_exceeded() -> str | None:
        if entries_examined >= max_entries:
            return f"entry budget exceeded ({max_entries})"
        if clock() - start >= max_seconds:
            return f"time budget exceeded ({max_seconds:g} seconds)"
        return None

    for root in normalized_roots:
        if stopped:
            break
        exceeded = budget_exceeded()
        if exceeded:
            review.append(exceeded)
            partial = stopped = True
            break
        try:
            root_stat = os.stat(root, follow_symlinks=False)
        except FileNotFoundError:
            if root in {"/opt", "/bin", "/sbin"}:
                continue
            review.append(f"{root}: required scan root is missing")
            partial = True
            continue
        except OSError as error:
            review.append(
                f"{root}: root metadata unavailable: "
                f"{error.strerror or error.__class__.__name__}"
            )
            partial = True
            continue
        if stat.S_ISLNK(root_stat.st_mode):
            try:
                target = os.readlink(root)
                resolved_target = os.path.normpath(
                    target if os.path.isabs(target) else os.path.join(os.path.dirname(root), target)
                )
            except OSError as error:
                review.append(
                    f"{root}: symbolic-link root could not be inspected: "
                    f"{error.strerror or error.__class__.__name__}"
                )
                partial = True
                continue
            if root in {"/bin", "/sbin"} and (
                resolved_target == "/usr" or resolved_target.startswith("/usr/")
            ):
                continue
            review.append(f"{root}: symbolic-link root was not followed")
            partial = True
            continue
        try:
            if not stat.S_ISDIR(root_stat.st_mode):
                review.append(f"{root}: scan root is missing, inaccessible, or not a real directory")
                partial = True
                continue
            root_mount = _mount_for_path(root, mounts)
            if root_mount is None:
                review.append(f"{root}: no mount context could be matched")
                partial = True
                continue
        except OSError as error:
            review.append(f"{root}: root could not be opened safely: {error.strerror or error.__class__.__name__}")
            partial = True
            continue

        stack: list[tuple[str, os.stat_result, MountInfo]] = [(root, root_stat, root_mount)]
        while stack:
            current_path, expected_stat, current_mount = stack.pop()
            exceeded = budget_exceeded()
            if exceeded:
                review.append(exceeded)
                partial = stopped = True
                break
            try:
                directory_fd = _open_directory_beneath_root(
                    root, root_stat, current_path, expected_stat
                )
            except OSError as error:
                review.append(
                    f"{current_path}: directory could not be opened safely: "
                    f"{error.strerror or error.__class__.__name__}"
                )
                partial = True
                continue
            children: list[tuple[str, os.stat_result, MountInfo]] = []
            try:
                with os.scandir(directory_fd) as iterator:
                    for entry in iterator:
                        name = entry.name
                        if not isinstance(name, str):
                            review.append(f"{current_path}: non-text entry name could not be assessed")
                            partial = True
                            continue
                        exceeded = budget_exceeded()
                        if exceeded:
                            review.append(exceeded)
                            partial = stopped = True
                            break
                        entries_examined += 1
                        path = os.path.join(current_path, name)
                        try:
                            raw = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        except OSError as error:
                            review.append(
                                f"{path}: metadata unavailable: {error.strerror or error.__class__.__name__}"
                            )
                            partial = True
                            continue

                        if stat.S_ISDIR(raw.st_mode):
                            child_mount = _mount_for_path(path, mounts)
                            if child_mount is not None and child_mount.mount_point == path:
                                continue
                            children.append((path, raw, child_mount or current_mount))
                            continue

                        if not stat.S_ISREG(raw.st_mode) or not raw.st_mode & 0o6000:
                            continue
                        try:
                            metadata = normalize_file_metadata(
                                path,
                                raw,
                                uid_mapped=id_is_mapped(raw.st_uid, uid_ranges, overflow_uid),
                                gid_mapped=id_is_mapped(raw.st_gid, gid_ranges, overflow_gid),
                            )
                        except (AttributeError, ValueError) as error:
                            review.append(f"{path}: metadata could not be normalized: {error}")
                            partial = True
                            continue
                        is_elf, signature_reason = _inspect_elf_signature(
                            directory_fd, name, raw
                        )
                        reasons = [reason for reason in (id_mapping_reason, signature_reason) if reason]
                        files.append(
                            SetIdFile(
                                metadata=metadata,
                                is_elf=is_elf,
                                mount_options=tuple(sorted(current_mount.options)),
                                reason="; ".join(reasons) or None,
                            )
                        )
                        if reasons:
                            review.append(f"{path}: {'; '.join(reasons)}")
                            partial = True
            except OSError as error:
                review.append(
                    f"{current_path}: directory could not be read: "
                    f"{error.strerror or error.__class__.__name__}"
                )
                partial = True
            finally:
                os.close(directory_fd)
            if stopped:
                break
            stack.extend(reversed(children))

    elapsed = max(0.0, clock() - start)
    status = CoverageStatus.PARTIAL if partial else CoverageStatus.COLLECTED
    return FilesystemCoverage(
        files=tuple(files),
        status=status,
        roots=normalized_roots,
        entries_examined=entries_examined,
        elapsed_seconds=elapsed,
        review=tuple(review),
    )
