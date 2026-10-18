"""Temporary bridge from the new AreaResult model to the legacy report.

During the migration, areas already moved to the Area contract return an
``AreaResult``; the existing terminal, HTML, Markdown and JSON renderers still
consume ``ScanResult``/``ReportSection``. This module converts one into the
other and is deleted once the renderers read ``AreaResult`` directly.

Some areas need a dedicated converter so the legacy view keeps showing what it
showed before the migration. Those converters live here, on purpose, and go
away with the bridge.
"""

from __future__ import annotations

from collections.abc import Callable

from vulpnix.cli.report import ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.core import AreaResult, AreaStatus, FindingStatus
from vulpnix.scan.privilege import PrivilegeContext
from vulpnix.scan.result import ScanResult


def _ssh_host_keys_section(result: AreaResult, details: bool) -> ReportSection:
    """Counts plus an attention list, as the legacy host-key view showed them."""
    facts = result.facts
    passed = tuple(fact for fact in facts if fact.status is FindingStatus.PASS)
    failed = sum(fact.status is FindingStatus.FAIL for fact in facts)
    review = sum(fact.status is FindingStatus.REVIEW for fact in facts)
    attention = tuple(
        f"[{finding.status.value}] {finding.evidence}" for finding in result.findings
    ) + tuple(f"[NOT_ASSESSED] {gap.message}" for gap in result.gaps)
    if details:
        shown = tuple(
            f"[PASS] {fact.label}: {fact.value}; contents were not read" for fact in passed
        ) + attention
    else:
        shown = attention[:6]
    items = shown or ("Host-key metadata checks passed; key contents were not read.",)
    if not details and len(attention) > len(shown):
        items += (
            f"{len(attention) - len(shown)} additional item(s) omitted; "
            "use --details to list them.",
        )
    return ReportSection(
        title=result.title,
        facts=(
            ("Keys/observations", str(len(facts) + len(result.gaps))),
            ("Metadata checks passed", str(len(passed))),
            ("Verified issues", str(failed)),
            ("Review", str(review)),
            ("Unavailable/error", str(len(result.gaps))),
        ),
        items=items,
        items_label="Host-key metadata:",
        footer=" ".join(result.notes) or None,
    )


_LEGACY_SECTIONS: dict[str, Callable[[AreaResult, bool], ReportSection]] = {
    "ssh_host_keys": _ssh_host_keys_section,
}


def area_result_to_section(result: AreaResult, *, details: bool = False) -> ReportSection:
    """Convert one area into a legacy section."""
    if result.status in {AreaStatus.NOT_ASSESSED, AreaStatus.ERROR}:
        return ReportSection(
            result.title,
            status=result.status.value,
            message=" ".join(gap.message for gap in result.gaps),
        )
    builder = _LEGACY_SECTIONS.get(result.area_id)
    if builder is not None:
        return builder(result, details)
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
    details: bool = False,
) -> ScanResult:
    """Wrap one area as a legacy ScanResult.

    Coverage follows the new rule: an area is PARTIAL only when something
    could not be collected or evaluated (its gaps). Findings that need review
    are counted separately by the summary and never hidden.
    """
    complete = result.status is AreaStatus.COMPLETE
    return ScanResult(
        sections=(area_result_to_section(result, details=details),),
        findings=result.findings,
        scope=scope,
        coverage=AssessmentCoverage.COMPLETE if complete else AssessmentCoverage.PARTIAL,
        review_items=len(result.gaps),
        privilege=privilege,
    )
