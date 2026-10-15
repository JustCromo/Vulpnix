"""Qualitative risk assessment for verified findings."""

from dataclasses import dataclass
from enum import Enum

from vulpnix.findings.model import Finding, FindingStatus
from vulpnix.risk.profiles import DEFAULT_PROFILES


@dataclass(frozen=True, slots=True)
class ScoredRisk:
    rule_id: str
    title: str
    impact: int
    probability: int
    score: int
    level: "RiskLevel"
    rationale: str
    evidence: str


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    scored: tuple[ScoredRisk, ...]
    unscored_verified: tuple[Finding, ...]


class RiskLevel(Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _valid_factor(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= 5
    )


def _risk_level(score: int) -> RiskLevel:
    if score <= 4:
        return RiskLevel.LOW
    if score <= 9:
        return RiskLevel.MODERATE
    if score <= 16:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def assess_findings(findings) -> RiskAssessment:
    """Score verified FAIL findings with explicit or documented default factors.

    REVIEW, NOT_ASSESSED, ERROR, and PASS findings are excluded. When a
    finding supplies any risk field itself, its supplied values must be
    complete and valid; an incomplete or invalid custom profile is not
    silently replaced by a default.
    """
    scored: list[ScoredRisk] = []
    unscored_verified: list[Finding] = []

    for finding in findings:
        if finding.status is not FindingStatus.FAIL:
            continue

        impact = finding.impact
        probability = finding.probability
        rationale = finding.risk_rationale

        # Apply a default profile only when no custom risk data was supplied.
        if impact is None and probability is None and rationale is None:
            profile = DEFAULT_PROFILES.get(finding.rule_id)
            if profile is not None:
                impact = profile.impact
                probability = profile.probability
                rationale = profile.rationale

        if (
            not _valid_factor(impact)
            or not _valid_factor(probability)
            or not isinstance(rationale, str)
            or not rationale.strip()
        ):
            unscored_verified.append(finding)
            continue

        score = impact * probability
        scored.append(
            ScoredRisk(
                rule_id=finding.rule_id,
                title=finding.title,
                impact=impact,
                probability=probability,
                score=score,
                level=_risk_level(score),
                rationale=rationale.strip(),
                evidence=finding.evidence,
            )
        )

    return RiskAssessment(
        scored=tuple(scored),
        unscored_verified=tuple(unscored_verified),
    )


@dataclass(frozen=True, slots=True)
class HostRiskScore:
    """Observed score derived from eligible verified findings."""

    score: int
    level: RiskLevel | None
    scored_findings: int
    unscored_verified: int


def assess_host_risk(assessment: RiskAssessment) -> HostRiskScore:
    """Use the maximum eligible Impact × Probability score, not a sum.

    A zero score means no eligible verified FAIL finding was scored. It does
    not establish that a host is secure if coverage is incomplete or a
    verified finding could not be scored.
    """
    highest = max(assessment.scored, key=lambda item: item.score, default=None)
    return HostRiskScore(
        score=highest.score if highest else 0,
        level=highest.level if highest else None,
        scored_findings=len(assessment.scored),
        unscored_verified=len(assessment.unscored_verified),
    )
