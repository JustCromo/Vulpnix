"""Structured, evidence-backed assessment findings."""

from dataclasses import dataclass
from enum import Enum


class FindingStatus(Enum):
    """Central status vocabulary for findings."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"
    REVIEW = "REVIEW"


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
