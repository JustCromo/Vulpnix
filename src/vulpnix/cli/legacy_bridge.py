"""Temporary bridge from the new AreaResult model to the legacy report.

During the migration, areas already moved to the Area contract return an
``AreaResult``; the existing terminal, HTML, Markdown and JSON renderers still
consume ``ScanResult``/``ReportSection``. This module converts one into the
other and is deleted once the renderers read ``AreaResult`` directly.
"""

from __future__ import annotations

from vulpnix.cli.report import ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.core import AreaResult, AreaStatus
from vulpnix.scan.privilege import PrivilegeContext
from vulpnix.scan.result import ScanResult


def area_result_to_section(result: AreaResult) -> ReportSection:
    """Render-neutral conversion of one area into a legacy section."""
    if result.status in {AreaStatus.NOT_ASSESSED, AreaStatus.ERROR}:
        return ReportSection(
            result.title,
            status=result.status.value,
            message=" ".join(gap.message for gap in result.gaps),
        )
    return ReportSection(
        result.title,
        table=tuple((fact.label, fact.value) for fact in result.facts),
        items=tuple(f"Review: {gap.message}" for gap in result.gaps),
        footer=" ".join(result.notes) or None,
    )


def area_result_to_scan_result(
    result: AreaResult,
    *,
    privilege: PrivilegeContext | None,
    scope: tuple[str, ...],
) -> ScanResult:
    """Wrap one area as a legacy ScanResult.

    Coverage follows the new rule: an area is PARTIAL only when something
    could not be collected or evaluated (its gaps). Findings that need review
    are counted separately by the summary and never hidden.
    """
    complete = result.status is AreaStatus.COMPLETE
    return ScanResult(
        sections=(area_result_to_section(result),),
        findings=result.findings,
        scope=scope,
        coverage=AssessmentCoverage.COMPLETE if complete else AssessmentCoverage.PARTIAL,
        review_items=len(result.gaps),
        privilege=privilege,
    )
