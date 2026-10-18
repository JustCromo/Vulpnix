"""Make every human-facing string in an area result safe to display.

Everything Vulpnix observes (file names, process names, account names, command
output) can be chosen by someone else, and Vulpnix often runs as root. A single
unfiltered escape sequence can clear the screen, hide findings, retitle the
terminal or write to the clipboard; unfiltered newlines can forge extra report
lines. This module is the one enforced boundary: ``run_area`` applies it to
every result, so no area and no renderer has to remember to.

Control characters become U+FFFD and very long strings are cut, so the displayed
text is always one bounded, printable piece of data.
"""

from __future__ import annotations

from dataclasses import replace

from vulpnix.core.results import AreaResult, Fact, Gap, Record
from vulpnix.core.text import printable
from vulpnix.findings import Finding

MAX_TEXT = 4096


def clean(value, *, limit: int = MAX_TEXT):
    """Sanitize a string or a tuple of strings; leave other values untouched."""
    if isinstance(value, str):
        text = printable(value)
        return text if len(text) <= limit else text[: limit - 1] + "…"
    if isinstance(value, tuple):
        return tuple(clean(item, limit=limit) for item in value)
    return value


def _finding(finding: Finding) -> Finding:
    return replace(
        finding,
        title=clean(finding.title),
        evidence=clean(finding.evidence),
        explanation=clean(finding.explanation),
        recommendation=clean(finding.recommendation),
        risk_rationale=clean(finding.risk_rationale),
    )


def _fact(fact: Fact) -> Fact:
    return replace(
        fact,
        key=clean(fact.key),
        label=clean(fact.label),
        value=clean(fact.value),
        raw=clean(fact.raw),
        detail=clean(fact.detail),
    )


def _record(record: Record) -> Record:
    return replace(
        record,
        kind=clean(record.kind),
        key=clean(record.key),
        label=clean(record.label),
        fields=tuple((clean(name), clean(value)) for name, value in record.fields),
    )


def _gap(gap: Gap) -> Gap:
    return replace(
        gap,
        key=clean(gap.key),
        message=clean(gap.message),
        subject=clean(gap.subject),
        cause=clean(gap.cause),
    )


def sanitize_result(result: AreaResult) -> AreaResult:
    """Return the same result with every displayable string made safe."""
    return replace(
        result,
        title=clean(result.title),
        findings=tuple(_finding(item) for item in result.findings),
        facts=tuple(_fact(item) for item in result.facts),
        records=tuple(_record(item) for item in result.records),
        gaps=tuple(_gap(item) for item in result.gaps),
        notes=clean(result.notes),
    )
