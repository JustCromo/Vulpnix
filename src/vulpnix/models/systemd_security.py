"""Normalized metadata observations for systemd unit files and drop-ins."""

from dataclasses import dataclass

from vulpnix.findings import Finding, FindingStatus


@dataclass(frozen=True, slots=True)
class UnitFileObservation:
    unit: str
    path: str
    owner_uid: int | None
    mode: int | None
    is_regular: bool | None
    is_symlink: bool
    error: str | None = None


@dataclass(frozen=True, slots=True)
class UnitFileCheck:
    unit: str
    path: str
    status: FindingStatus
    evidence: str
    recommendation: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class UnitFileAssessment:
    checks: tuple[UnitFileCheck, ...]
    findings: tuple[Finding, ...]
    review: tuple[str, ...] = ()

    @property
    def incomplete_checks(self) -> int:
        return sum(check.status in {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR} for check in self.checks)

    @property
    def review_items(self) -> int:
        return sum(check.status is not FindingStatus.PASS for check in self.checks) + len(self.review)
