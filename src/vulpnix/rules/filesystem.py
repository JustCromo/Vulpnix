"""Evidence-based checks for sensitive file metadata."""

from dataclasses import dataclass

from vulpnix.findings import Finding, FindingStatus
from vulpnix.models import (
    CoverageStatus,
    FileMetadata,
    FileMetadataResult,
    FileMetadataStatus,
    FilesystemCoverage,
)

_SENSITIVE_SECRET_FILES = {"/etc/shadow", "/etc/gshadow"}
_SENSITIVE_FILES = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
}


@dataclass(frozen=True, slots=True)
class FilesystemReview:
    """A metadata item that needs review rather than a security conclusion."""

    path: str
    reason: str
    metadata: FileMetadata | None = None


@dataclass(frozen=True, slots=True)
class FilesystemAssessment:
    """Rule results separated into evaluated entries and unresolved review."""

    checked: tuple[FileMetadata, ...]
    review: tuple[FilesystemReview, ...]
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class SetIdAssessment:
    """Set-ID conclusions and unresolved items, separate from collection."""

    assessed: int
    active: int
    disabled: int
    review: tuple[str, ...]
    findings: tuple[Finding, ...]


def _evidence(metadata: FileMetadata) -> str:
    return (
        f"Path: {metadata.path}; UID: {metadata.uid if metadata.uid is not None else 'unavailable'}; "
        f"GID: {metadata.gid if metadata.gid is not None else 'unavailable'}; "
        f"mode: {metadata.mode:04o}; type: {metadata.type}"
    )


def assess_sensitive_files(
    results: tuple[FileMetadataResult, ...],
) -> FilesystemAssessment:
    """Evaluate only explicit, verifiable conditions on the four fixed files."""
    checked: list[FileMetadata] = []
    review: list[FilesystemReview] = []
    findings: list[Finding] = []

    for result in results:
        metadata = result.metadata
        if result.path not in _SENSITIVE_FILES:
            review.append(FilesystemReview(result.path, "path is outside the fixed assessment scope"))
            continue
        if result.status is FileMetadataStatus.NOT_ASSESSED or metadata is None:
            review.append(FilesystemReview(result.path, result.reason or "metadata unavailable"))
            continue
        if metadata.path != result.path:
            review.append(FilesystemReview(result.path, "result and metadata paths do not match", metadata))
            continue
        if metadata.uid is None:
            review.append(
                FilesystemReview(
                    metadata.path,
                    "owner UID is not mapped in the current user namespace",
                    metadata,
                )
            )
        if metadata.gid is None:
            review.append(
                FilesystemReview(
                    metadata.path,
                    "owner GID is not mapped in the current user namespace",
                    metadata,
                )
            )
        if metadata.type != "regular file":
            review.append(
                FilesystemReview(
                    metadata.path,
                    f"expected a regular file; found {metadata.type}",
                    metadata,
                )
            )
            continue

        checked.append(metadata)
        evidence = _evidence(metadata)
        if metadata.uid is not None and metadata.uid != 0:
            findings.append(
                Finding(
                    rule_id="FS-SENSITIVE-OWNER-001",
                    title="Sensitive system file is not owned by UID 0",
                    evidence=evidence,
                    explanation=(
                        "A non-root owner can change the file's contents or permissions, "
                        "which can affect local account and authentication data."
                    ),
                    recommendation=(
                        "Verify the intended ownership and restore root ownership if the "
                        "current owner is not explicitly required."
                    ),
                    status=FindingStatus.FAIL,
                )
            )
        if metadata.mode & 0o022:
            findings.append(
                Finding(
                    rule_id="FS-SENSITIVE-WRITE-001",
                    title="Sensitive system file is writable by group or others",
                    evidence=evidence,
                    explanation=(
                        "Group or other write permission allows an account beyond the "
                        "owner to change sensitive local account data."
                    ),
                    recommendation=(
                        "Review the owning group and remove group/other write access "
                        "unless it is explicitly required and controlled."
                    ),
                    status=FindingStatus.FAIL,
                )
            )
        if metadata.path in _SENSITIVE_SECRET_FILES and metadata.mode & 0o004:
            findings.append(
                Finding(
                    rule_id="FS-SECRET-WORLD-READ-001",
                    title="Credential file is readable by all local users",
                    evidence=evidence,
                    explanation=(
                        "The other-read permission exposes shadow credential metadata "
                        "to every local account."
                    ),
                    recommendation=(
                        "Remove world-read access and retain only the access required "
                        "by the host's account-management configuration."
                    ),
                    status=FindingStatus.FAIL,
                )
            )
        elif metadata.path in _SENSITIVE_SECRET_FILES and metadata.mode & 0o040:
            review.append(
                FilesystemReview(
                    metadata.path,
                    "group-readable; group membership and policy were not assessed",
                    metadata,
                )
            )

    return FilesystemAssessment(tuple(checked), tuple(review), tuple(findings))


def assess_setid_files(coverage: FilesystemCoverage) -> SetIdAssessment:
    """Fail only on a verified world-writable, active set-ID ELF executable."""
    assessed = active = disabled = 0
    review = list(coverage.review)
    findings: list[Finding] = []
    for item in coverage.files:
        metadata = item.metadata
        path = metadata.path
        setuid_active = bool(metadata.mode & 0o4000 and metadata.mode & 0o111)
        setgid_active = bool(metadata.mode & 0o2000 and metadata.mode & 0o010)
        if not (setuid_active or setgid_active):
            continue
        if metadata.type != "regular file":
            review.append(f"{path}: set-ID entry is not a regular file")
            continue
        if metadata.uid is None or metadata.gid is None:
            review.append(f"{path}: ownership mapping is unavailable")
            continue
        if item.is_elf is None:
            review.append(f"{path}: ELF signature could not be verified")
            continue
        if not item.is_elf:
            review.append(f"{path}: set-ID file is not identified as ELF")
            continue
        if item.mount_options is None:
            review.append(f"{path}: mount execution options are unavailable")
            continue
        if {"nosuid", "noexec"}.intersection(item.mount_options):
            disabled += 1
            assessed += 1
            continue
        active += 1
        assessed += 1
        if metadata.mode & 0o002:
            kind = "SUID" if setuid_active else "SGID"
            if setuid_active and setgid_active:
                kind = "SUID/SGID"
            findings.append(
                Finding(
                    rule_id="FS-SETID-WORLD-WRITE-001",
                    title="Active set-ID ELF file is world-writable",
                    evidence=(
                        f"Path: {path}; type: {metadata.type}; set-ID: {kind}; "
                        f"UID: {metadata.uid}; GID: {metadata.gid}; "
                        f"mode: {metadata.mode:04o}; mount options: "
                        f"{','.join(item.mount_options)}"
                    ),
                    explanation=(
                        "Any local account can modify this executable while its set-ID "
                        "permissions are active, allowing the modified program to run "
                        "with its configured effective identity."
                    ),
                    recommendation=(
                        "Remove world-write access and verify the file's intended owner, "
                        "group, and package integrity."
                    ),
                    status=FindingStatus.FAIL,
                )
            )
    return SetIdAssessment(
        assessed=assessed,
        active=active,
        disabled=disabled,
        review=tuple(review),
        findings=tuple(findings),
    )
