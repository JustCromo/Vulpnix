"""Assessment rules for the ownership and write permissions of systemd unit files."""

from vulpnix.findings import Finding, FindingStatus
from vulpnix.models import UnitFileAssessment, UnitFileObservation, UnitFileCheck


def assess_systemd_unit_metadata(
    observations: tuple[UnitFileObservation, ...],
    collection_review: tuple[str, ...] = (),
) -> UnitFileAssessment:
    checks: list[UnitFileCheck] = []
    findings: list[Finding] = []
    for item in observations:
        if item.error:
            check = UnitFileCheck(item.unit, item.path, FindingStatus.NOT_ASSESSED, f"{item.path}: {item.error}", "Retry with privileges needed to inspect the unit file metadata.", item.error)
        elif item.is_symlink:
            check = UnitFileCheck(item.unit, item.path, FindingStatus.REVIEW, f"{item.path} is a symbolic link; link target metadata was not followed", "Verify that the link target resolves to an intended, root-controlled systemd configuration file.", "symbolic link was not followed")
        elif item.is_regular is not True:
            check = UnitFileCheck(item.unit, item.path, FindingStatus.REVIEW, f"{item.path} is not a regular file", "Review the fragment or drop-in path and its systemd semantics.", "unexpected file type")
        elif item.owner_uid is None or item.mode is None:
            missing = []
            if item.owner_uid is None:
                missing.append("owner UID")
            if item.mode is None:
                missing.append("permission mode")
            check = UnitFileCheck(item.unit, item.path, FindingStatus.NOT_ASSESSED, f"{item.path}: missing metadata: {', '.join(missing)}", "Retry with sufficient permissions and verify the unit-file metadata before drawing a conclusion.", "required metadata unavailable")
        else:
            reasons = []
            if item.owner_uid != 0:
                reasons.append(f"owner UID {item.owner_uid} is not root")
            if item.mode & 0o022:
                reasons.append("group/other write permission is present")
            if reasons:
                check = UnitFileCheck(item.unit, item.path, FindingStatus.FAIL, f"{item.path}: " + "; ".join(reasons), "Make system service unit files and drop-ins root-owned and not writable by group or other users.")
            else:
                check = UnitFileCheck(item.unit, item.path, FindingStatus.PASS, f"{item.path}: root-owned, mode {item.mode:04o}", "No action required for these metadata checks.")
        checks.append(check)
        if check.status is not FindingStatus.PASS:
            findings.append(Finding(
                rule_id="SYSTEMD-UNIT-METADATA-001",
                title=(f"Systemd unit metadata is unsafe: {item.unit}" if check.status is FindingStatus.FAIL else f"Systemd unit metadata requires review: {item.unit}"),
                evidence=check.evidence,
                explanation="A system service definition writable by an unprivileged account may allow privileged code execution when the service is started. Unknown or symlink metadata is not treated as a confirmed vulnerability.",
                recommendation=check.recommendation,
                status=check.status,
                severity="HIGH" if check.status is FindingStatus.FAIL else None,
            ))
    return UnitFileAssessment(tuple(checks), tuple(findings), collection_review)
