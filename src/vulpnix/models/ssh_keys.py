"""Metadata-only observations for SSH host private keys."""

from dataclasses import dataclass

from vulpnix.findings import Finding, FindingStatus


@dataclass(frozen=True, slots=True)
class SSHHostKeyObservation:
    path: str
    owner_uid: int | None
    mode: int | None
    is_regular: bool | None
    is_symlink: bool
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SSHHostKeyCheck:
    path: str
    status: FindingStatus
    evidence: str
    recommendation: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class SSHHostKeyAssessment:
    checks: tuple[SSHHostKeyCheck, ...]
    findings: tuple[Finding, ...]

    @property
    def incomplete_checks(self) -> int:
        return sum(check.status in {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR} for check in self.checks)

    @property
    def review_items(self) -> int:
        return sum(check.status is not FindingStatus.PASS for check in self.checks)
