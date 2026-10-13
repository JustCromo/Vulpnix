"""Normalized observations and assessments for Linux kernel hardening."""

from dataclasses import dataclass

from vulpnix.findings import Finding, FindingStatus


@dataclass(frozen=True, slots=True)
class SysctlObservation:
    key: str
    value: str | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class HardeningCheck:
    rule_id: str
    title: str
    key: str
    observed: str | None
    expected: str
    status: FindingStatus
    explanation: str
    recommendation: str
    reason: str | None = None
    optional: bool = False


@dataclass(frozen=True, slots=True)
class HardeningAssessment:
    checks: tuple[HardeningCheck, ...]
    findings: tuple[Finding, ...]

    @property
    def incomplete_checks(self) -> int:
        return sum(
            check.status in {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR}
            and not check.optional
            for check in self.checks
        )

    @property
    def review_items(self) -> int:
        return sum(
            check.status in {
                FindingStatus.FAIL,
                FindingStatus.REVIEW,
                FindingStatus.NOT_ASSESSED,
                FindingStatus.ERROR,
            }
            for check in self.checks
        )
