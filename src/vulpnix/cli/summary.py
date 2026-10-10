"""Presentation-level aggregation for assessment findings and coverage."""

from dataclasses import dataclass
from enum import Enum

from vulpnix.findings import Finding, FindingStatus


class AssessmentResult(Enum):
    NO_VERIFIED_ISSUES = "NO VERIFIED ISSUES"
    REVIEW_REQUIRED = "REVIEW REQUIRED"
    ISSUES_DETECTED = "ISSUES DETECTED"


class AssessmentCoverage(Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"


@dataclass(frozen=True, slots=True)
class AssessmentSummary:
    """Categorical result derived from existing findings and review coverage."""

    title: str
    result: AssessmentResult
    coverage: AssessmentCoverage
    verified_findings: int
    review_items: int
    severity_breakdown: tuple[tuple[str, int], ...]
    category_coverage: tuple[tuple[str, AssessmentCoverage], ...]
    failed_categories: tuple[str, ...]
    description: str
    action: str


def build_assessment_summary(
    *,
    findings: tuple[Finding, ...],
    coverage: AssessmentCoverage,
    review_items: int,
    title: str = "VULPNIX RESULT",
    category_coverage: tuple[tuple[str, AssessmentCoverage], ...] = (),
    failed_categories: tuple[str, ...] = (),
) -> AssessmentSummary:
    """Aggregate existing finding statuses without adding security judgments."""
    verified = tuple(
        finding for finding in findings if finding.status is FindingStatus.FAIL
    )
    unresolved_findings = sum(
        finding.status in {
            FindingStatus.REVIEW,
            FindingStatus.NOT_ASSESSED,
            FindingStatus.ERROR,
        }
        for finding in findings
    )
    total_review_items = max(0, review_items) + unresolved_findings

    if verified:
        result = AssessmentResult.ISSUES_DETECTED
        description = f"Vulpnix verified {len(verified)} security issue(s)."
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        for finding in verified:
            severity = getattr(finding, "severity", None)
            severity_value = getattr(severity, "value", severity)
            normalized = str(severity_value).upper() if severity_value is not None else None
            if normalized in severity_counts:
                severity_counts[normalized] += 1
        available_severities = {
            str(
                getattr(
                    getattr(finding, "severity", None),
                    "value",
                    getattr(finding, "severity", None),
                )
            ).upper()
            for finding in verified
            if getattr(finding, "severity", None) is not None
        }
        severity_breakdown = tuple(
            (severity, count)
            for severity, count in severity_counts.items()
            if severity in available_severities
        )
        high_count = severity_counts["HIGH"]
        if high_count:
            action = (
                f"{high_count} high-severity issue(s) require attention. "
                "Review finding details and follow their recommendations."
            )
        else:
            action = (
                "Review verified findings and follow their listed recommendations."
            )
    elif total_review_items or coverage is AssessmentCoverage.PARTIAL:
        result = AssessmentResult.REVIEW_REQUIRED
        severity_breakdown = ()
        if coverage is AssessmentCoverage.PARTIAL:
            description = (
                "No verified security issues were found, but some checks "
                "could not be completed reliably."
            )
            action = (
                "No verified vulnerability requires immediate remediation. "
                "Review incomplete checks if full coverage is required."
            )
        else:
            description = (
                "No verified security issues were found, but one or more items "
                "need review."
            )
            action = (
                "No verified vulnerability requires immediate remediation. "
                "Review the flagged items for context."
            )
    else:
        result = AssessmentResult.NO_VERIFIED_ISSUES
        severity_breakdown = ()
        description = "No verified security issues were detected."
        action = "No immediate remediation is required."

    return AssessmentSummary(
        title=title,
        result=result,
        coverage=coverage,
        verified_findings=len(verified),
        review_items=total_review_items,
        severity_breakdown=severity_breakdown,
        category_coverage=category_coverage,
        failed_categories=failed_categories,
        description=description,
        action=action,
    )
