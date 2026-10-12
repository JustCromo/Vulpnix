from __future__ import annotations

from dataclasses import dataclass

from vulpnix.cli.report import ReportSection
from vulpnix.findings import Finding
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.models import SystemInfo
from vulpnix.scan.privilege import PrivilegeContext


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Normalized result produced by a scan operation."""

    sections: tuple[ReportSection, ...] = ()
    findings: tuple[Finding, ...] = ()
    scope: tuple[str, ...] = ()
    coverage: AssessmentCoverage = AssessmentCoverage.COMPLETE
    review_items: int = 0
    host: SystemInfo | None = None
    privilege: PrivilegeContext | None = None
