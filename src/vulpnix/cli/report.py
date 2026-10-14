"""Width-aware rendering for structured Vulpnix assessment reports."""

from dataclasses import dataclass

from vulpnix.cli.terminal import accent, display_width, wrap_text
from vulpnix.cli.summary import AssessmentCoverage, build_assessment_summary
from vulpnix.findings import Finding
from vulpnix.models import SystemInfo
from vulpnix.risk.engine import RiskAssessment
from vulpnix.scan.privilege import PrivilegeContext


@dataclass(frozen=True)
class ReportBlock:
    """A labeled presentation block with prose lines and named lists."""

    title: str
    lines: tuple[str, ...] = ()
    lists: tuple[tuple[str, tuple[str, ...]], ...] = ()


@dataclass(frozen=True)
class ReportSection:
    """Presentation data for one independently collected assessment area."""

    title: str
    facts: tuple[tuple[str, str], ...] = ()
    table: tuple[tuple[str, str], ...] = ()
    items: tuple[str, ...] = ()
    message: str | None = None
    status: str | None = None
    items_label: str | None = None
    footer: str | None = None
    blocks: tuple[ReportBlock, ...] = ()


@dataclass(frozen=True)
class ScanReport:
    """Structured content consumed by the terminal report renderer."""

    host: SystemInfo | None
    sections: tuple[ReportSection, ...]
    findings: tuple[Finding, ...]
    scope: tuple[str, ...]
    host_message: str | None = None
    risk_score: str | None = None
    risk_assessment: RiskAssessment | None = None
    coverage: AssessmentCoverage = AssessmentCoverage.COMPLETE
    review_items: int = 0
    privilege: PrivilegeContext | None = None
    details: bool = True


def _safe(value: object) -> str:
    text = str(value)
    return "".join(character if character.isprintable() else "�" for character in text)


def _uptime(seconds: float | None) -> str:
    if seconds is None:
        return "Unavailable"
    minutes = int(seconds // 60)
    days, remaining = divmod(minutes, 24 * 60)
    hours, remaining = divmod(remaining, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if remaining or not parts:
        parts.append(f"{remaining}m")
    return " ".join(parts)


def _wrap(value: str, width: int, *, indent: str = "") -> list[str]:
    return wrap_text(_safe(value), width, initial_indent=indent)


def _overview(report: ScanReport, width: int) -> list[str]:
    host = report.host
    if host is None:
        identity = report.host_message or "Host facts unavailable."
    else:
        identity = " · ".join(
            (
                _safe(host.hostname or "Unavailable"),
                _safe(host.distribution or "Unavailable"),
                _safe(host.architecture or "Unavailable"),
            )
        )

    count = len(report.findings)
    assessment = f"Findings: {count} · Scope: {' · '.join(report.scope)}"
    if report.risk_score is not None:
        assessment += f" · Risk score: {report.risk_score}"

    return [
        accent("OVERVIEW", bold=True),
        *_wrap(f"Host: {identity}", width),
        *_wrap(assessment, width),
    ]


def _finding_attention(findings: tuple[Finding, ...], width: int) -> list[str]:
    lines = [
        accent(line, bold=True)
        for line in _wrap(f"ATTENTION · {len(findings)}", width)
    ]
    if not findings:
        return [*lines, "  No findings reported."]

    for finding in findings:
        summary = f"⚠ {_finding_status(finding)} · {finding.title}"
        lines.extend(_wrap(summary, width - 2, indent="  "))
    return lines


def _finding_status(finding: Finding) -> str:
    status = getattr(finding, "status", None)
    if status is None:
        return "REVIEW"
    return str(getattr(status, "value", status))


def render_report_section(section: ReportSection, width: int) -> list[str]:
    """Render one structured section without collecting or assessing data."""
    title_lines = _wrap(section.title, width)
    lines = [accent(line, bold=True) for line in title_lines]
    if section.status:
        lines.extend(_wrap(f"Status: {section.status}", width - 2, indent="  "))
    if section.message:
        lines.extend(_wrap(section.message, width - 2, indent="  "))
    for label, value in section.facts:
        padding = " " * max(16 - display_width(label), 0)
        lines.extend(_wrap(f"{label}{padding} {value}", width - 2, indent="  "))
    if section.table:
        label_width = min(
            max(len("Option"), *(len(label) for label, _ in section.table)),
            30,
            max(width - 12, 8),
        )
        if width >= 56:
            lines.append(f"  {'OPTION':<{label_width}}  VALUE")
            for label, value in section.table:
                prefix = f"  {label:<{label_width}}  "
                wrapped = wrap_text(
                    _safe(value),
                    initial_indent=prefix,
                    subsequent_indent=" " * display_width(prefix),
                    width=width,
                )
                lines.extend(wrapped)
        else:
            for label, value in section.table:
                lines.extend(_wrap(label, width - 2, indent="  "))
                lines.extend(_wrap(value, width - 4, indent="    "))
    if section.items_label:
        lines.extend(_wrap(section.items_label, width - 2, indent="  "))
    for item in section.items:
        lines.extend(_wrap(f"• {item}", width - 4, indent="  "))
    if section.footer:
        lines.extend(_wrap(section.footer, width - 2, indent="  "))
    for block in section.blocks:
        lines.extend(("", accent(block.title, bold=True)))
        for line in block.lines:
            lines.extend(_wrap(line, width - 2, indent="  "))
        for label, items in block.lists:
            lines.extend(_wrap(label, width - 2, indent="  "))
            if items:
                for item in items:
                    lines.extend(_wrap(f"• {item}", width - 4, indent="    "))
            else:
                lines.extend(_wrap("None identified.", width - 4, indent="    "))
    return lines


def _finding_details(findings: tuple[Finding, ...], width: int) -> list[str]:
    lines = [accent(line, bold=True) for line in _wrap("FINDING DETAILS", width)]
    if not findings:
        lines.append("  No detailed findings.")
        return lines

    for finding in findings:
        lines.extend(
            _wrap(
                f"[{_finding_status(finding)}] {finding.title}",
                width - 2,
                indent="  ",
            )
        )
        lines.extend(_wrap(f"Rule: {finding.rule_id}", width - 4, indent="    "))
        for attribute in ("severity", "exposure"):
            value = getattr(finding, attribute, None)
            if value is not None:
                lines.extend(
                    _wrap(f"{attribute.title()}: {_safe(value)}", width - 4, indent="    ")
                )
        lines.extend(_wrap(f"Evidence: {finding.evidence}", width - 4, indent="    "))
        lines.extend(_wrap("Why it matters:", width - 4, indent="    "))
        lines.extend(_wrap(finding.explanation, width - 6, indent="      "))
        lines.extend(_wrap("Recommendation:", width - 4, indent="    "))
        lines.extend(_wrap(finding.recommendation, width - 6, indent="      "))
    return lines



def _risk_assessment_lines(
    assessment: RiskAssessment,
    width: int,
    *,
    details: bool,
) -> list[str]:
    """Render documented qualitative risk scores without scoring uncertain checks."""
    width = max(1, width)
    content_width = max(1, width - 2)
    lines = [
        accent(line, bold=True)
        for line in _wrap("RISK ASSESSMENT", width)
    ]

    lines.extend(
        _wrap(
            (
                f"Scored findings: {len(assessment.scored)} · "
                f"Verified but unscored: {len(assessment.unscored_verified)}"
            ),
            content_width,
            indent="  ",
        )
    )
    lines.extend(
        _wrap(
            "Scale: Impact 1–5 × qualitative probability 1–5; "
            "probability is not a statistical measurement.",
            content_width,
            indent="  ",
        )
    )
    lines.extend(
        _wrap(
            "Bands: LOW 1–4 · MODERATE 5–9 · HIGH 10–16 · CRITICAL 17–25.",
            content_width,
            indent="  ",
        )
    )
    lines.extend(
        _wrap(
            "Only verified FAIL findings with a complete valid profile are "
            "scored. PASS, REVIEW, NOT_ASSESSED and ERROR are excluded.",
            content_width,
            indent="  ",
        )
    )

    if assessment.scored:
        longest_rule_id = max(len(item.rule_id) for item in assessment.scored)
        if width >= 56 and longest_rule_id <= width - 34:
            name_width = max(10, longest_rule_id)
            lines.append(
                f"  {'RULE':<{name_width}}  {'IMPACT':>6}  "
                f"{'PROB.':>5}  {'SCORE':>5}  {'LEVEL':<8}"
            )
            for item in assessment.scored:
                lines.append(
                    f"  {item.rule_id:<{name_width}}  {item.impact:>6}  "
                    f"{item.probability:>5}  {item.score:>5}  "
                    f"{item.level.value:<8}"
                )
        else:
            for item in assessment.scored:
                lines.extend(
                    _wrap(item.rule_id, max(1, width - 4), indent="    ")
                )
                lines.extend(
                    _wrap(
                        f"Impact: {item.impact} · Probability: {item.probability} "
                        f"· Score: {item.score} · Level: {item.level.value}",
                        max(1, width - 4),
                        indent="    ",
                    )
                )

        if details:
            lines.extend(
                (
                    "",
                    *[
                        accent(line, bold=True)
                        for line in _wrap("RISK RATIONALE", width)
                    ],
                )
            )
            for item in assessment.scored:
                lines.extend(
                    _wrap(
                        f"{item.rule_id} · Score: {item.impact} × "
                        f"{item.probability} = {item.score} · {item.level.value}",
                        content_width,
                        indent="  ",
                    )
                )
                lines.extend(
                    _wrap(
                        f"Rationale: {item.rationale}",
                        max(1, width - 4),
                        indent="    ",
                    )
                )
    else:
        lines.extend(
            _wrap(
                "No verified FAIL findings with an eligible risk profile were scored.",
                content_width,
                indent="  ",
            )
        )

    if assessment.unscored_verified:
        lines.extend(
            _wrap(
                "Verified FAIL findings not scored (no complete valid documented profile):",
                content_width,
                indent="  ",
            )
        )
        for finding in assessment.unscored_verified:
            lines.extend(
                _wrap(
                    finding.rule_id,
                    max(1, width - 4),
                    indent="    ",
                )
            )

    return lines


def render_scan_report(report: ScanReport, width: int) -> list[str]:
    """Render a scan report, adapting cards and wrapped text to terminal width."""
    width = max(1, width)
    title_lines = _wrap("VULPNIX  /  LINUX HOST ASSESSMENT", width)
    lines = [
        accent(title_lines[0], bold=True),
        *title_lines[1:],
        *_wrap(f"Scope: {' · '.join(report.scope)}", width),
        "",
        *_overview(report, width),
        "",
        *_finding_attention(report.findings, width),
        "",
        accent("DETAILS", bold=True),
    ]
    has_system_section = any(section.title in {"SYSTEM", "HOST", "HOST DETAILS"} for section in report.sections)
    if report.host is not None and not has_system_section:
        distribution = report.host.distribution or "Unavailable"
        if report.host.distribution_version:
            distribution += f" ({report.host.distribution_version})"
        system_facts = (
            ("Host", report.host.hostname or "Unavailable"),
            ("Distribution", distribution),
            ("Kernel", report.host.kernel_release or "Unavailable"),
            ("Architecture", report.host.architecture or "Unavailable"),
            ("Uptime", _uptime(report.host.uptime_seconds)),
        )
        lines.extend(render_report_section(ReportSection("SYSTEM", facts=system_facts), width))
    for section in report.sections:
        lines.extend(render_report_section(section, width))

    if report.risk_assessment is not None:
        lines.extend(
            (
                "",
                *_risk_assessment_lines(
                    report.risk_assessment, width, details=report.details
                ),
            )
        )

    if report.details:
        lines.extend(("", *_finding_details(report.findings, width), ""))
    summary = build_assessment_summary(
        findings=report.findings,
        coverage=report.coverage,
        review_items=report.review_items,
    )

    lines.append("")
    lines.append(accent("FINAL RESULT", bold=True))
    icon = {
        "NO VERIFIED ISSUES": "✓",
        "REVIEW REQUIRED": "⚠",
        "ISSUES DETECTED": "✗",
    }.get(summary.result.value, "!")
    lines.append(f"  {icon} {summary.result.value}")
    if report.privilege is not None:
        mode = report.privilege.mode
        lines.extend(_wrap(f"  Execution mode: {mode} (UID {report.privilege.uid})", width - 2))
    lines.extend(_wrap(summary.description, width - 2, indent="  "))
    lines.extend(_wrap(summary.action, width - 2, indent="  "))
    if (
        report.privilege is not None
        and not report.privilege.privileged
        and report.coverage is AssessmentCoverage.PARTIAL
    ):
        lines.extend(_wrap("Some checks could not be completed with the current privileges.", width - 2, indent="  "))
        lines.extend(_wrap("Use elevated privileges to complete checks that need them: sudo vulpnix", width - 2, indent="  "))

    return lines
