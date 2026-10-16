"""Structured, evidence-backed assessment findings."""

from dataclasses import dataclass
import math
from enum import Enum


class FindingStatus(Enum):
    """Central status vocabulary for findings."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"
    REVIEW = "REVIEW"


@dataclass(frozen=True, slots=True)
class CVSSScore:
    """One CVSS base assessment supplied by a trusted vulnerability source."""

    version: str
    base_score: float
    severity: str
    vector: str
    source: str | None = None

    def __post_init__(self) -> None:
        try:
            score = float(self.base_score)
        except (TypeError, ValueError) as error:
            raise ValueError("CVSS base score must be a number from 0 to 10.") from error

        if not math.isfinite(score) or not 0.0 <= score <= 10.0:
            raise ValueError("CVSS base score must be finite and between 0 and 10.")
        if not self.version.strip():
            raise ValueError("CVSS version must not be empty.")
        if not self.severity.strip():
            raise ValueError("CVSS severity must not be empty.")
        if not self.vector.strip():
            raise ValueError("CVSS vector must not be empty.")

        object.__setattr__(self, "base_score", score)


@dataclass(frozen=True, slots=True)
class CVEAssessment:
    """A CVE identifier and all CVSS base assessments available for it."""

    cve_id: str
    cvss: tuple[CVSSScore, ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    """A rule result with its evidence and a practical review suggestion."""

    rule_id: str
    title: str
    evidence: str
    explanation: str
    recommendation: str
    status: FindingStatus = FindingStatus.REVIEW
    severity: str | None = None
    impact: int | None = None
    probability: int | None = None
    risk_rationale: str | None = None
    cves: tuple[CVEAssessment, ...] = ()
