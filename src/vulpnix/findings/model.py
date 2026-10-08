"""Structured, evidence-backed assessment findings."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Finding:
    """A rule result with its evidence and a practical review suggestion."""

    rule_id: str
    title: str
    evidence: str
    explanation: str
    recommendation: str
