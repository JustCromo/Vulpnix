"""Assessment rules for SSH host private-key metadata, never key contents."""

from vulpnix.findings import Finding, FindingStatus
from vulpnix.models import SSHHostKeyAssessment, SSHHostKeyCheck, SSHHostKeyObservation


def assess_ssh_host_key_metadata(observations: tuple[SSHHostKeyObservation, ...]) -> SSHHostKeyAssessment:
    checks: list[SSHHostKeyCheck] = []
    findings: list[Finding] = []
    for item in observations:
        if item.error:
            status = FindingStatus.NOT_ASSESSED
            evidence = f"{item.path}: {item.error}"
            recommendation = "Rerun with appropriate privileges or verify whether the OpenSSH host keys exist."
            check = SSHHostKeyCheck(item.path, status, evidence, recommendation, item.error)
        elif item.is_symlink:
            status = FindingStatus.REVIEW
            evidence = f"{item.path} is a symbolic link; its target was not inspected"
            recommendation = "Verify the key target and ensure only root can change the target or the link."
            check = SSHHostKeyCheck(item.path, status, evidence, recommendation, "symbolic link was not followed")
        elif item.is_regular is not True:
            status = FindingStatus.REVIEW
            evidence = f"{item.path} is not a regular file"
            recommendation = "Verify the configured host-key storage and metadata manually."
            check = SSHHostKeyCheck(item.path, status, evidence, recommendation, "unexpected file type")
        elif item.owner_uid is None or item.mode is None:
            status = FindingStatus.NOT_ASSESSED
            missing = []
            if item.owner_uid is None:
                missing.append("owner UID")
            if item.mode is None:
                missing.append("permission mode")
            evidence = f"{item.path}: missing metadata: {', '.join(missing)}"
            recommendation = "Retry with sufficient permissions and verify the key metadata before drawing a conclusion."
            check = SSHHostKeyCheck(item.path, status, evidence, recommendation, "required metadata unavailable")
        else:
            problems: list[str] = []
            if item.owner_uid != 0:
                problems.append(f"owner UID is {item.owner_uid}, expected 0")
            if item.mode & 0o077:
                problems.append(f"mode {item.mode:04o} allows group/other access")
            if problems:
                status = FindingStatus.FAIL
                evidence = f"{item.path}: " + "; ".join(problems)
                recommendation = "Set the key owner to root and remove group/other permissions after confirming the intended OpenSSH key path."
                check = SSHHostKeyCheck(item.path, status, evidence, recommendation)
            else:
                status = FindingStatus.PASS
                evidence = f"{item.path}: root-owned regular file, mode {item.mode:04o}; contents were not read"
                recommendation = "No action required for these metadata checks."
                check = SSHHostKeyCheck(item.path, status, evidence, recommendation)

        checks.append(check)
        if check.status is not FindingStatus.PASS:
            findings.append(Finding(
                rule_id="SSH-HOST-KEY-METADATA-001",
                title=("SSH host private-key metadata is unsafe" if check.status is FindingStatus.FAIL else f"SSH host-key metadata requires review: {item.path}"),
                evidence=check.evidence,
                explanation=("Host private keys should be controlled by root and not readable or writable by other users. This check uses filesystem metadata only and never reads key material."),
                recommendation=check.recommendation,
                status=check.status,
                severity="HIGH" if check.status is FindingStatus.FAIL else None,
            ))
    return SSHHostKeyAssessment(tuple(checks), tuple(findings))
