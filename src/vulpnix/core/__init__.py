"""Terminal-independent data model shared by areas, engine and renderers."""

from vulpnix.core.results import AreaResult, AreaStatus, Fact, Gap
from vulpnix.findings import CVEAssessment, CVSSScore, Finding, FindingStatus

__all__ = [
    "AreaResult",
    "AreaStatus",
    "CVEAssessment",
    "CVSSScore",
    "Fact",
    "Finding",
    "FindingStatus",
    "Gap",
]
