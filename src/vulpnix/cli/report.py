"""Width-aware rendering for structured Vulpnix assessment reports."""

from dataclasses import dataclass

from vulpnix.cli.terminal import accent, display_width, wrap_text
from vulpnix.findings import Finding
from vulpnix.models import SystemInfo


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
    if report.host is not None:
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
        system_section = ReportSection("SYSTEM", facts=system_facts)
    else:
        system_section = ReportSection(
            "SYSTEM", message=report.host_message or "Host facts unavailable."
        )

    lines.extend(render_report_section(system_section, width))
    for section in report.sections:
        lines.extend(render_report_section(section, width))

    lines.extend(("", *_finding_details(report.findings, width), ""))
    lines.append(accent("SUMMARY", bold=True))
    lines.extend(_wrap("No aggregate risk score is calculated.", width - 2, indent="  "))
    lines.extend(
        _wrap(
            "Configuration facts only; this is not a complete access test.",
            width - 2,
            indent="  ",
        )
    )
    return lines
