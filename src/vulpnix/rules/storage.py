"""Conservative capacity and temporary-mount assessment rules."""

import math
import re

from vulpnix.findings import Finding, FindingStatus
from vulpnix.models.storage import (
    MountedFilesystem,
    StorageSnapshot,
    StorageStatus,
)


DEFAULT_LOW_SPACE_PERCENT = 5.0
DEFAULT_CRITICAL_SPACE_PERCENT = 1.0
DEFAULT_LOW_INODE_PERCENT = 5.0

# Only check optional hardening flags on dedicated mounts at these paths.
# The rules intentionally do not claim that `noexec` is universally required.
TEMPORARY_MOUNT_POINTS = frozenset({"/tmp", "/var/tmp", "/dev/shm"})


def _mount_id(path: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "-", path.upper()).strip("-") or "ROOT"


def _validate_thresholds(
    low_space_percent: float,
    critical_space_percent: float,
    low_inode_percent: float,
) -> None:
    values = (low_space_percent, critical_space_percent, low_inode_percent)
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 < value <= 100
        for value in values
    ):
        raise ValueError("Review thresholds must be finite percentages in (0, 100].")
    if critical_space_percent > low_space_percent:
        raise ValueError(
            "critical_space_percent must not exceed low_space_percent"
        )


def _space_finding(
    filesystem: MountedFilesystem,
    percent_available: float,
    *,
    threshold: float,
    critical: bool,
) -> Finding:
    status_text = (
        "Critically low available storage"
        if critical
        else "Low available storage"
    )
    mount = filesystem.mount_point
    title = f"{status_text} on {mount} ({percent_available:.1f}% available)"
    evidence = (
        f"mount={mount}; filesystem={filesystem.fs_type or 'unknown'}; "
        f"source={filesystem.source or 'unknown'}; "
        f"available_bytes={filesystem.available_bytes}; "
        f"total_bytes={filesystem.total_bytes}; "
        f"available_percent={percent_available:.2f}; "
        f"review_threshold_percent={threshold:.1f}"
    )
    return Finding(
        rule_id=f"STORAGE-SPACE-LOW-{_mount_id(mount)}",
        title=title,
        evidence=evidence,
        explanation=(
            f"Only {percent_available:.1f}% of the reported filesystem capacity "
            f"is available to unprivileged workloads, below the documented "
            f"{threshold:.1f}% review threshold. This indicates possible "
            "resource exhaustion; it does not by itself establish a security vulnerability."
        ),
        recommendation=(
            "Review large files, logs, caches and retention policies. "
            "Verify backups and the purpose of any data before removing it."
        ),
        status=FindingStatus.REVIEW,
    )


def _inode_finding(
    filesystem: MountedFilesystem,
    percent_available: float,
    threshold: float,
) -> Finding:
    mount = filesystem.mount_point
    return Finding(
        rule_id=f"STORAGE-INODES-LOW-{_mount_id(mount)}",
        title=(
            f"Low available inode capacity on {mount} "
            f"({percent_available:.1f}% available)"
        ),
        evidence=(
            f"mount={mount}; filesystem={filesystem.fs_type or 'unknown'}; "
            f"available_inodes={filesystem.available_inodes}; "
            f"total_inodes={filesystem.total_inodes}; "
            f"available_percent={percent_available:.2f}; "
            f"review_threshold_percent={threshold:.1f}"
        ),
        explanation=(
            f"Only {percent_available:.1f}% of reported inodes are available, "
            f"below the documented {threshold:.1f}% review threshold. "
            "Creating files can fail even while byte capacity remains available."
        ),
        recommendation=(
            "Review directories containing very large numbers of small files "
            "and confirm application-specific cleanup or retention policies."
        ),
        status=FindingStatus.REVIEW,
    )


def _temporary_mount_finding(
    filesystem: MountedFilesystem,
    missing_options: tuple[str, ...],
) -> Finding:
    mount = filesystem.mount_point
    missing_text = ", ".join(missing_options)
    return Finding(
        rule_id=f"FILESYSTEM-TEMP-MOUNT-OPTIONS-{_mount_id(mount)}",
        title=f"Review hardening options for dedicated temporary mount {mount}",
        evidence=(
            f"mount={mount}; filesystem={filesystem.fs_type or 'unknown'}; "
            f"source={filesystem.source or 'unknown'}; "
            f"observed_options={','.join(filesystem.mount_options)}; "
            f"missing_common_options={missing_text}"
        ),
        explanation=(
            f"This dedicated temporary mount lacks the common hardening option(s) "
            f"{missing_text}. Applicability depends on the workload and mount design, "
            "so this is a review item rather than a confirmed vulnerability."
        ),
        recommendation=(
            "Review whether nosuid and nodev are appropriate for this dedicated "
            "temporary filesystem. Confirm application requirements before changing "
            "mount configuration."
        ),
        status=FindingStatus.REVIEW,
    )


def assess_storage(
    snapshot: StorageSnapshot,
    *,
    low_space_percent: float = DEFAULT_LOW_SPACE_PERCENT,
    critical_space_percent: float = DEFAULT_CRITICAL_SPACE_PERCENT,
    low_inode_percent: float = DEFAULT_LOW_INODE_PERCENT,
) -> tuple[Finding, ...]:
    """Return review findings for measurable resource pressure or mount policy.

    Missing metrics do not become passes or failures. Storage pressure and
    contextual mount-option concerns are REVIEW items, not scored vulnerabilities.
    """
    _validate_thresholds(
        low_space_percent,
        critical_space_percent,
        low_inode_percent,
    )

    if snapshot.status is StorageStatus.NOT_ASSESSED:
        return ()

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for filesystem in snapshot.filesystems:
        if filesystem.status is not StorageStatus.COLLECTED:
            continue

        total_bytes = filesystem.total_bytes
        available_bytes = filesystem.available_bytes
        if (
            total_bytes is not None
            and total_bytes > 0
            and available_bytes is not None
            and 0 <= available_bytes <= total_bytes
        ):
            percent_available = available_bytes * 100.0 / total_bytes
            if percent_available <= low_space_percent:
                key = ("space", filesystem.mount_point)
                if key not in seen:
                    findings.append(
                        _space_finding(
                            filesystem,
                            percent_available,
                            threshold=(
                                critical_space_percent
                                if percent_available <= critical_space_percent
                                else low_space_percent
                            ),
                            critical=percent_available <= critical_space_percent,
                        )
                    )
                    seen.add(key)

        total_inodes = filesystem.total_inodes
        available_inodes = filesystem.available_inodes
        if (
            total_inodes is not None
            and total_inodes > 0
            and available_inodes is not None
            and 0 <= available_inodes <= total_inodes
        ):
            percent_available = available_inodes * 100.0 / total_inodes
            if percent_available <= low_inode_percent:
                key = ("inodes", filesystem.mount_point)
                if key not in seen:
                    findings.append(
                        _inode_finding(
                            filesystem,
                            percent_available,
                            low_inode_percent,
                        )
                    )
                    seen.add(key)

        if filesystem.mount_point in TEMPORARY_MOUNT_POINTS:
            options = set(filesystem.mount_options)
            missing = tuple(
                option
                for option in ("nosuid", "nodev")
                if option not in options
            )
            if missing:
                key = ("temp-options", filesystem.mount_point)
                if key not in seen:
                    findings.append(
                        _temporary_mount_finding(filesystem, missing)
                    )
                    seen.add(key)

    return tuple(findings)
