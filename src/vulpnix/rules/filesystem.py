"""Evidence-based checks for sensitive file metadata."""

from dataclasses import dataclass

from vulpnix.findings import Finding
from vulpnix.models import FileMetadata, FileMetadataResult, FileMetadataStatus

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
