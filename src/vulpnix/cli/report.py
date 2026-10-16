"""Width-aware rendering for structured Vulpnix assessment reports."""

from dataclasses import dataclass

from vulpnix.cli.terminal import accent, color, display_width, wrap_text
from vulpnix.cli.summary import AssessmentCoverage, build_assessment_summary
from vulpnix.findings import Finding
from vulpnix.models import SystemInfo
from vulpnix.risk.engine import RiskAssessment, assess_findings, assess_host_risk
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
        if report.host_message:
            identity = report.host_message
        elif any(
            section.title in {"SYSTEM", "HOST", "HOST DETAILS"}
            for section in report.sections
        ):
            # Host data was expected but was not collected successfully.
            identity = "Host facts unavailable."
        else:
            identity = "Host facts not collected for this scan."
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
        status = _finding_status(finding)
        text = f"⚠ {status} · {finding.title}"
        lines.extend(_color_wrapped(
            text,
            width - 2,
            indent="  ",
            status=status,
        ))
    return lines

def _finding_status(finding: Finding) -> str:
    status = getattr(finding, "status", None)
    if status is None:
        return "REVIEW"
    return str(getattr(status, "value", status))



_STATUS_RGB = {
    "PASS": (134, 239, 172),
    "FAIL": (255, 112, 112),
    "REVIEW": (255, 205, 128),
    "NOT_ASSESSED": (166, 173, 186),
    "ERROR": (255, 112, 112),
    "LOW": (134, 239, 172),
    "MEDIUM": (255, 205, 128),
    "MODERATE": (255, 205, 128),
    "HIGH": (255, 151, 97),
    "CRITICAL": (255, 112, 112),
}


def _normalize_status(value):
    value = str(getattr(value, "value", value) or "").strip().upper()
    if value in _STATUS_RGB:
        return value
    return {
        "OK": "PASS",
        "COMPLETE": "PASS",
        "COLLECTED": "PASS",
        "HEALTHY": "PASS",
        "FAILED": "FAIL",
        "PARTIAL": "REVIEW",
        "REVIEW REQUIRED": "REVIEW",
        "UNAVAILABLE": "NOT_ASSESSED",
        "UNSUPPORTED": "NOT_ASSESSED",
        "NOT ASSESSED": "NOT_ASSESSED",
        "NO VERIFIED ISSUES": "PASS",
        "ISSUES DETECTED": "FAIL",
    }.get(value)


def _risk_status(level):
    level = str(getattr(level, "value", level) or "").upper()
    return {
        "LOW": "PASS",
        "MODERATE": "REVIEW",
        "HIGH": "FAIL",
        "CRITICAL": "FAIL",
    }.get(level, "NOT_ASSESSED")


def _status_color(text, status, *, bold=False):
    status = _normalize_status(status)
    rgb = _STATUS_RGB.get(status)
    if rgb is None:
        return accent(text, bold=bold)
    return color(text, rgb, bold=bold)


def _color_wrapped(text, width, *, indent="", status=None, bold=False):
    wrapped = _wrap(text, max(1, width), indent=indent)
    if status is None:
        return wrapped
    return [
        _status_color(line, status, bold=bold)
        for line in wrapped
    ]


def _line_status(line):
    text = str(line).strip()
    upper = text.upper()

    for status in ("NOT_ASSESSED", "ERROR", "FAIL", "REVIEW", "PASS"):
        if upper.startswith((
            f"[{status}]",
            f"{status} ·",
            f"{status}:",
            f"{status} ",
        )):
            return status

    if upper.startswith(("UNAVAILABLE:", "UNSUPPORTED:")):
        return "NOT_ASSESSED"
    if upper.startswith("✓"):
        return "PASS"
    if upper.startswith("✗"):
        return "FAIL"
    if upper.startswith("⚠"):
        return "REVIEW"
    if "could not be evaluated for account state" in upper:
        return "NOT_ASSESSED"
    if "could not be assessed" in upper or "permission denied" in upper:
        return "NOT_ASSESSED"
    if upper.startswith(("REVIEW:", "REVIEW ")):
        return "REVIEW"
    if upper.startswith(("ERROR:", "ERROR ")):
        return "ERROR"

    return None


def _leading_count(value):
    tokens = str(value).strip().split()
    if not tokens:
        return None
    try:
        return int(tokens[0].rstrip(",;"))
    except ValueError:
        return None


def _fact_status(label, value):
    key = str(label).strip().lower()
    text = str(value).strip().lower()
    count = _leading_count(value)

    verified_counts = {
        "verified concerns",
        "verified issues",
        "verified findings",
        "set-id verified findings",
    }
    review_counts = {
        "context review",
        "review",
        "review findings",
        "review matches",
        "set-id review items",
        "mount-option reviews",
        "low available storage",
        "low available inodes",
    }
    unavailable_counts = {
        "unavailable/error",
        "unavailable",
        "not assessed",
        "errors",
    }
    passing_counts = {
        "checks passing",
        "metadata checks passed",
        "metadata passed",
    }

    if key in verified_counts and count is not None:
        return "FAIL" if count > 0 else "PASS"

    if key in review_counts and count is not None:
        return "REVIEW" if count > 0 else "PASS"

    if key in unavailable_counts and count is not None:
        return "NOT_ASSESSED" if count > 0 else "PASS"

    if key in passing_counts and count is not None and count > 0:
        return "PASS"

    # Advisory matches are not automatically verified vulnerabilities.
    if key == "confirmed matches" and count is not None:
        return "REVIEW" if count > 0 else "PASS"

    if key == "empty passwords":
        if text in {"yes", "true", "enabled"}:
            return "FAIL"
        if text in {"no", "false", "disabled"}:
            return "PASS"

    if key == "password authentication":
        if text in {"yes", "true", "enabled"}:
            return "REVIEW"
        if text in {"no", "false", "disabled"}:
            return "PASS"

    if key == "root login":
        if text in {"yes", "password", "password and keys"}:
            return "REVIEW"
        if text in {"no", "key login only", "prohibit-password"}:
            return "PASS"

    if key in {
        "audit status",
        "inventory status",
        "collection status",
        "status",
    }:
        return _normalize_status(value)

    return None


def _fact_value_lines(
    label: str,
    value: object,
    width: int,
    *,
    indent: str = "  ",
    align_label: bool = False,
) -> list[str]:
    """Keep fact labels neutral and style only recognized result values."""
    label_text = str(label)
    padding = (
        " " * max(16 - display_width(label_text), 0)
        if align_label
        else ""
    )
    prefix = (
        f"{indent}{label_text}{padding} "
        if align_label
        else f"{indent}{label_text}: "
    )
    available_width = max(1, width - display_width(prefix))
    value_lines = _wrap(_safe(value), available_width) or [""]
    status = _fact_status(label_text, value)
    continuation = " " * display_width(prefix)
    rendered = []

    for index, value_line in enumerate(value_lines):
        content = (
            _status_color(value_line, status)
            if status is not None
            else value_line
        )
        rendered.append(
            (prefix if index == 0 else continuation) + content
        )

    return rendered


def _section_semantic_status(section):
    statuses = []

    explicit = _normalize_status(section.status)
    if explicit:
        statuses.append(explicit)

    for label, value in section.facts:
        result = _fact_status(label, value)
        if result:
            statuses.append(result)

    for label, value in section.table:
        result = _fact_status(label, value)
        if result:
            statuses.append(result)

    lines = list(section.items)
    if section.message:
        lines.append(section.message)

    for block in section.blocks:
        lines.extend(block.lines)
        if block.title.upper() == "REVIEW":
            meaningful = [
                line for line in block.lines
                if not any(phrase in line.lower() for phrase in (
                    "no unresolved",
                    "all defined filesystem checks completed",
                    "all available hardening parameters matched",
                    "no files require additional detail",
                ))
            ]
            if meaningful:
                statuses.append("REVIEW")

    for line in lines:
        status = _line_status(line)
        if status:
            statuses.append(status)

        # Some assessment blocks express a count in prose rather than
        # starting each line with a status marker.
        if ":" in line:
            label, value = line.split(":", 1)
            status = _fact_status(label, value.strip())
            if status:
                statuses.append(status)

    for status in ("FAIL", "ERROR", "REVIEW", "NOT_ASSESSED", "PASS"):
        if status in statuses:
            return status

    return None


def _section_heading(section):
    """Keep section titles neutral; color individual assessment outcomes."""
    return section.title


def _append_final_finding_summary(lines, report, width):
    """Name verified issues and show their actual recommended actions."""
    content_width = max(1, width - 2)
    verified = [
        finding for finding in report.findings
        if _finding_status(finding) == "FAIL"
    ]
    unresolved = [
        finding for finding in report.findings
        if _finding_status(finding) in {"REVIEW", "NOT_ASSESSED", "ERROR"}
    ]


    if verified:
        lines.append("")
        lines.extend(_color_wrapped(
            f"VERIFIED ISSUE(S) · {len(verified)}",
            content_width,
            status="FAIL",
            bold=True,
        ))

        visible = verified[:3]
        for finding in visible:
            lines.extend(_color_wrapped(
                _compact_finding_title(finding),
                content_width,
                indent="  ",
                status="FAIL",
                bold=True,
            ))

            recommendation = str(finding.recommendation or "").strip()
            if recommendation:
                lines.extend(_color_wrapped(
                    "Recommended action:",
                    content_width,
                    indent="    ",
                    status="REVIEW",
                    bold=True,
                ))
                lines.extend(_wrap(
                    recommendation,
                    content_width,
                    indent="      ",
                ))
            else:
                lines.extend(_wrap(
                    "Recommendation unavailable; inspect finding details.",
                    content_width,
                    indent="    ",
                ))

        omitted = len(verified) - len(visible)
        if omitted:
            text = (
                f"{omitted} additional verified issue(s) are listed in FINDING DETAILS."
                if report.details
                else f"{omitted} additional verified issue(s) omitted; use --details."
            )
            lines.extend(_wrap(text, content_width, indent="  "))

    if unresolved:
        lines.extend(_wrap(
            f"Findings requiring review or further assessment: {len(unresolved)} "
            "(not all are confirmed vulnerabilities).",
            content_width,
            indent="  ",
        ))

    if report.review_items:
        lines.extend(_wrap(
            f"Additional review/coverage items reported by checks: {report.review_items}.",
            content_width,
            indent="  ",
        ))

def render_report_section(section: ReportSection, width: int) -> list[str]:
    """Render one structured section with semantic status styling."""
    title_lines = _wrap(section.title, width)
    lines = list(title_lines)

    if section.status:
        lines.extend(_color_wrapped(
            f"Status: {section.status}",
            width - 2,
            indent="  ",
            status=_normalize_status(section.status),
        ))

    if section.message:
        lines.extend(_wrap(section.message, width - 2, indent="  "))

    for label, value in section.facts:
        lines.extend(_fact_value_lines(
            label,
            value,
            width - 2,
            indent="  ",
            align_label=True,
        ))

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
                table_status = _fact_status(label, value)
                if table_status:
                    wrapped = [
                        (
                            line[:len(prefix)]
                            + _status_color(line[len(prefix):], table_status)
                            if line.startswith(prefix)
                            else _status_color(line, table_status)
                        )
                        for line in wrapped
                    ]
                lines.extend(wrapped)
        else:
            for label, value in section.table:
                lines.extend(_wrap(label, width - 2, indent="  "))
                lines.extend(_color_wrapped(
                    value,
                    width - 4,
                    indent="    ",
                    status=_fact_status(label, value),
                ))

    if section.items_label:
        lines.extend(_wrap(section.items_label, width - 2, indent="  "))

    for item in section.items:
        lines.extend(_color_wrapped(
            f"• {item}",
            width - 4,
            indent="  ",
            status=_line_status(item),
        ))

    if section.footer:
        lines.extend(_wrap(section.footer, width - 2, indent="  "))

    for block in section.blocks:
        if block.title.upper() == "REVIEW":
            block_status = "REVIEW"
        else:
            block_status = _section_semantic_status(
                ReportSection(title=block.title, items=block.lines)
            )

        lines.append("")
        if block_status:
            lines.append(_status_color(block.title, block_status, bold=True))
        else:
            lines.append(accent(block.title, bold=True))

        for line in block.lines:
            lines.extend(_color_wrapped(
                line,
                width - 2,
                indent="  ",
                status=_line_status(line),
            ))

        for label, items in block.lists:
            lines.extend(_wrap(label, width - 2, indent="  "))
            if items:
                for item in items:
                    lines.extend(_color_wrapped(
                        f"• {item}",
                        width - 4,
                        indent="    ",
                        status=_line_status(item),
                    ))
            else:
                lines.extend(_wrap("None identified.", width - 4, indent="    "))

    return lines

def _finding_details(findings: tuple[Finding, ...], width: int) -> list[str]:
    lines = [accent(line, bold=True) for line in _wrap("FINDING DETAILS", width)]
    if not findings:
        lines.append("  No detailed findings.")
        return lines

    for finding in findings:
        status = _finding_status(finding)
        lines.extend(_color_wrapped(
            f"[{status}] {finding.title}",
            width - 2,
            indent="  ",
            status=status,
        ))
        lines.extend(_wrap(f"Rule: {finding.rule_id}", width - 4, indent="    "))
        for attribute in ("severity", "exposure"):
            value = getattr(finding, attribute, None)
            if value is not None:
                lines.extend(_wrap(
                    f"{attribute.title()}: {_safe(value)}",
                    width - 4,
                    indent="    ",
                ))
        for cve in getattr(finding, "cves", ()):
            cve_id = _safe(getattr(cve, "cve_id", ""))
            cvss_scores = getattr(cve, "cvss", ())

            if not cvss_scores:
                label = f"{cve_id} · CVSS unavailable" if cve_id else (
                    "CVSS unavailable (no valid vector recorded)"
                )
                lines.extend(_color_wrapped(
                    label,
                    width - 4,
                    indent="    ",
                    status="NOT_ASSESSED",
                    bold=True,
                ))
                continue

            for score in cvss_scores:
                version = _safe(getattr(score, "version", "unknown"))
                base_score = float(score.base_score)
                severity = str(
                    getattr(getattr(score, "severity", ""), "value",
                            getattr(score, "severity", ""))
                    or ""
                ).strip().upper()

                color_status = (
                    severity
                    if severity in {"LOW", "MEDIUM", "MODERATE", "HIGH", "CRITICAL"}
                    else "NOT_ASSESSED"
                )
                label = f"{cve_id} · " if cve_id else ""
                label += f"CVSS {version}: {base_score:.1f} · {severity or 'UNKNOWN'}"

                lines.extend(_color_wrapped(
                    label,
                    width - 4,
                    indent="    ",
                    status=color_status,
                    bold=True,
                ))

                source = getattr(score, "source", None)
                if source:
                    lines.extend(_wrap(
                        f"CVSS source: {_safe(source)}",
                        width - 8,
                        indent="        ",
                    ))

                vector = getattr(score, "vector", None)
                if vector:
                    lines.extend(_wrap(
                        f"CVSS vector: {_safe(vector)}",
                        width - 8,
                        indent="        ",
                    ))

        lines.extend(_wrap(f"Evidence: {finding.evidence}", width - 4, indent="    "))
        lines.extend(_wrap("Why it matters:", width - 4, indent="    "))
        lines.extend(_wrap(finding.explanation, width - 6, indent="      "))
        lines.extend(_color_wrapped(
            "Recommendation:",
            width - 4,
            indent="    ",
            status="REVIEW",
            bold=True,
        ))
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



_SUMMARY_FACT_PRIORITIES = {
    "SYSTEM": ("Hostname", "Distribution", "Kernel"),
    "HOST": ("Hostname", "Distribution", "Kernel"),
    "HOST DETAILS": ("Hostname", "Distribution", "Kernel"),
    "KERNEL HARDENING": (
        "Parameters checked", "Checks passing", "Verified concerns",
        "Context review", "Unavailable/error",
    ),
    "NETWORK EXPOSURE": (
        "Sockets", "TCP listeners", "UDP bound sockets",
        "All interfaces", "Process attribution",
    ),
    "USERS": ("Local accounts", "UID 0 accounts", "Privileged accounts"),
    "SERVICES": ("Units", "State", "Startup enabled"),
    "SOFTWARE INVENTORY": (
        "Package manager", "Installed packages", "Inventory status",
    ),
    "PACKAGE VULNERABILITY AUDIT": (
        "Advisory source", "Packages checked", "Confirmed matches",
        "Review matches", "Audit status",
    ),
    "DISK & FILESYSTEM CAPACITY": (
        "Low available storage", "Low available inodes",
        "Mount-option reviews", "Collection status",
    ),
}


def _compact_section_lines(section: ReportSection, width: int) -> list[str]:
    """Show key metrics and unresolved notes, not the section's full inventory."""
    lines = _wrap(_section_heading(section), width)
    content_width = max(1, width - 2)

    if section.status and section.status.upper() not in {"OK", "COMPLETE", "PASS"}:
        lines.extend(_wrap(f"Status: {section.status}", content_width, indent="  "))

    if section.message:
        lines.extend(_wrap(section.message, content_width, indent="  "))

    facts = dict(section.facts)
    priority = _SUMMARY_FACT_PRIORITIES.get(section.title, ())
    selected = [(label, facts[label]) for label in priority if label in facts]

    if not selected and section.facts:
        selected = list(section.facts[:3])

    if selected:
        for label, value in selected:
            lines.extend(_fact_value_lines(
                label,
                value,
                content_width,
                indent="  ",
            ))

    if section.table:
        # Keep the compact SSH summary readable and color only result values.
        # No key or file contents are exposed.
        for label, value in section.table[:4]:
            lines.extend(_fact_value_lines(
                label,
                value,
                content_width,
                indent="  ",
            ))

    # Collector diagnostics remain visible, but routine inventory rows do not.
    diagnostic_items = []
    for item in section.items:
        upper = item.upper()
        lower = item.lower()
        if (
            upper.startswith(("REVIEW:", "ERROR:", "NOT_ASSESSED:", "UNAVAILABLE:", "UNSUPPORTED:"))
            or any(phrase in lower for phrase in (
                "could not be completed",
                "could not be assessed",
                "could not be confirmed",
                "timed out",
                "failed to collect",
            ))
        ):
            diagnostic_items.append(item)

    # Keep representative network inventory visible in compact output.
    if section.title == "NETWORK EXPOSURE":
        truncation_note = next(
            (
                item for item in section.items
                if "additional socket(s) omitted" in item.lower()
            ),
            None,
        )
        if truncation_note:
            lines.extend(_wrap(truncation_note, content_width, indent="  "))

    elif section.title == "NETWORK INTERFACES":
        interface_names = []
        for item in section.items:
            candidate = item.strip()
            lower = candidate.lower()
            if (
                not candidate
                or lower.startswith(
                    ("review:", "error:", "not_assessed:", "unavailable:", "unsupported:")
                )
                or "additional interface" in lower
                or "no network interface" in lower
            ):
                continue

            for prefix in ("Interface: ", "Interface ", "Name: "):
                if candidate.lower().startswith(prefix.lower()):
                    candidate = candidate[len(prefix):]
                    break

            for delimiter in (" | ", " · ", "; ", ": "):
                if delimiter in candidate:
                    candidate = candidate.split(delimiter, 1)[0]
                    break
            else:
                candidate = candidate.split()[0] if candidate.split() else ""

            candidate = candidate.strip().rstrip(":,")
            if candidate and candidate not in interface_names:
                interface_names.append(candidate)
            if len(interface_names) >= 3:
                break

        if interface_names:
            lines.extend(_wrap(
                "Interface examples: " + ", ".join(interface_names),
                content_width,
                indent="  ",
            ))

    # Preserve firewall scope and limitations without dumping rule details.
    if section.title == "FIREWALL POLICY ANALYSIS":
        if section.items_label:
            lines.extend(_wrap(section.items_label, content_width, indent="  "))
        lines.extend(_wrap(
            "Scope: firewall input and forwarding policy analysis is partial.",
            content_width,
            indent="  ",
        ))
        if section.footer:
            lines.extend(_wrap(
                "Note: " + section.footer,
                content_width,
                indent="  ",
            ))

    if section.title == "SERVICES" and section.items:
        service_names = [
            item for item in section.items
            if item
            and not item.startswith("No active, startup-enabled services found.")
            and "additional service(s) omitted" not in item
        ]
        if service_names:
            lines.extend(_wrap(
                "Active, startup-enabled examples: " + ", ".join(service_names[:3]),
                content_width,
                indent="  ",
            ))
            if len(service_names) > 3:
                lines.extend(_wrap(
                    f"{len(service_names) - 3} additional service(s) omitted; use --details.",
                    content_width,
                    indent="  ",
                ))

    for item in diagnostic_items[:2]:
        lines.extend(_wrap(f"Review: {item}", content_width, indent="  "))
    if len(diagnostic_items) > 2:
        lines.extend(_wrap(
            f"{len(diagnostic_items) - 2} additional diagnostic note(s) omitted; use --details.",
            content_width,
            indent="  ",
        ))

    # Keep the file-assessment summary concise while preserving real review items.
    if section.title == "FILESYSTEM":
        assessment_block = next(
            (block for block in section.blocks if block.title.upper() == "ASSESSMENT"),
            None,
        )
        if assessment_block:
            metrics = [
                line for line in assessment_block.lines
                if not line.lstrip().upper().startswith(
                    ("[FAIL]", "[REVIEW]", "[ERROR]", "[NOT_ASSESSED]", "FAIL ·", "REVIEW ·")
                )
                and "no defined insecure condition" not in line.lower()
            ]
            for line in metrics[:2]:
                lines.extend(_wrap(line, content_width, indent="  "))

    for block in section.blocks:
        block_title = block.title.upper()

        if section.title == "FILESYSTEM" and block_title == "FACTS":
            summary_facts = [
                line for line in block.lines
                if line.startswith((
                    "Set-ID regular files:",
                    "Set-ID verified findings:",
                ))
            ]
            if summary_facts:
                lines.extend(_wrap(
                    " · ".join(summary_facts),
                    content_width,
                    indent="  ",
                ))
            continue

        # User access and other concise assessment outcomes are useful without
        # exposing full inventories. Filesystem metrics are summarized above.
        if block_title == "ASSESSMENT" and section.title != "FILESYSTEM":
            assessment_lines = [
                line for line in block.lines
                if not any(phrase in line.lower() for phrase in (
                    "no unresolved",
                    "all defined filesystem checks completed",
                    "all available hardening parameters matched",
                    "no files require additional detail",
                ))
            ]
            # Keep account-state coverage visible even beyond the normal limit.
            selected_assessment_lines = list(assessment_lines[:3])
            for line in assessment_lines:
                if (
                    "could not be evaluated for account state" in line.lower()
                    and line not in selected_assessment_lines
                ):
                    selected_assessment_lines.append(line)

            for line in selected_assessment_lines:
                lines.extend(_wrap(line, content_width, indent="  "))

            omitted_assessment_count = (
                len(assessment_lines) - len(selected_assessment_lines)
            )
            if omitted_assessment_count > 0:
                lines.extend(_wrap(
                    f"{omitted_assessment_count} additional assessment note(s) omitted; use --details.",
                    content_width,
                    indent="  ",
                ))
            continue

        if section.title == "FILESYSTEM" and block_title == "DETAILS":
            not_assessed_lines = [
                line for line in block.lines
                if " · NOT_ASSESSED · " in line.upper()
            ]
            for line in not_assessed_lines[:4]:
                lines.extend(_wrap(
                    f"Review: {line}",
                    content_width,
                    indent="  ",
                ))
            continue

        if block_title != "REVIEW":
            continue

        review_lines = [
            line for line in block.lines
            if not any(phrase in line.lower() for phrase in (
                "no unresolved",
                "all defined filesystem checks completed",
                "all available hardening parameters matched",
                "no files require additional detail",
            ))
        ]
        review_limit = 4 if section.title == "FILESYSTEM" else 2
        visible_reviews = list(review_lines[:review_limit])

        if section.title == "USERS":
            for line in review_lines:
                if (
                    "could not be evaluated for account state" in line.lower()
                    and line not in visible_reviews
                ):
                    visible_reviews.append(line)

        for line in visible_reviews:
            lines.extend(_wrap(f"Review: {line}", content_width, indent="  "))

        omitted_reviews = len(review_lines) - len(visible_reviews)
        if omitted_reviews > 0:
            lines.extend(_wrap(
                f"{omitted_reviews} additional review item(s) omitted; use --details.",
                content_width,
                indent="  ",
            ))

    if section.title == "PACKAGE VULNERABILITY AUDIT":
        lines.extend(_wrap(
            "Advisory coverage depends on the source and supported ecosystem; "
            "no matching result does not prove absence of vulnerabilities.",
            content_width,
            indent="  ",
        ))
    elif section.title == "NETWORK EXPOSURE":
        lines.extend(_wrap(
            "Listening sockets do not by themselves prove internet reachability or vulnerability.",
            content_width,
            indent="  ",
        ))

    return lines



def _compact_host_identity(report: ScanReport) -> str:
    """Give host identity a clear value even in targeted or failed scans."""
    if report.host is not None:
        host = report.host
        return " · ".join((
            _safe(host.hostname or "Unavailable"),
            _safe(host.distribution or "Unavailable"),
            _safe(host.architecture or "Unavailable"),
        ))

    for section in report.sections:
        if section.title not in {"SYSTEM", "HOST", "HOST DETAILS"}:
            continue

        status = (section.status or "").upper()
        if status in {"NOT_ASSESSED", "ERROR"}:
            return "Host facts unavailable."

        facts = dict(section.facts)
        parts = [
            facts[label]
            for label in ("Hostname", "Distribution", "Architecture")
            if facts.get(label)
        ]
        if parts:
            return " · ".join(_safe(part) for part in parts)

        if section.message:
            return section.message

    if report.host_message:
        return report.host_message

    return "Host facts not collected for this scan."


def _compact_finding_title(finding: Finding) -> str:
    """Keep compact finding titles short while retaining an affected path."""
    title = " ".join(str(finding.title).split())
    evidence = str(finding.evidence or "")
    path = None

    for fragment in evidence.replace("\\n", ";").split(";"):
        candidate = fragment.strip()
        if candidate.lower().startswith("path:"):
            path = candidate.split(":", 1)[1].strip()
            break

    if path and path not in title:
        suffix = f" (Path: {path})"
        if len(title) + len(suffix) > 120:
            available = max(1, 120 - len(suffix) - 1)
            title = title[:available].rstrip() + "…" + suffix
        else:
            title += suffix
        return title

    if len(title) > 120:
        return title[:117].rstrip() + "…"
    return title


def _host_risk_summary_lines(report: ScanReport, width: int) -> list[str]:
    """Always display a scoped observed risk score and its coverage qualifier."""
    content_width = max(1, width - 2)
    assessment = report.risk_assessment or assess_findings(report.findings)
    score = assess_host_risk(assessment)

    incomplete_findings = any(
        _finding_status(finding) in {"REVIEW", "NOT_ASSESSED", "ERROR"}
        for finding in report.findings
    )
    limited = (
        report.coverage is AssessmentCoverage.PARTIAL
        or report.review_items > 0
        or incomplete_findings
        or score.unscored_verified > 0
    )

    if score.level is not None:
        score_status = _risk_status(score.level.value)
        score_text = f"Observed host risk score: {score.score}/25 · {score.level.value}"
    else:
        score_status = (
            "NOT_ASSESSED" if score.unscored_verified
            else "REVIEW" if limited
            else "PASS"
        )
        score_text = f"Observed host risk score: {score.score}/25"

    lines = [
        *[
            accent(line, bold=True)
            for line in _wrap("HOST RISK SCORE · CURRENT SCAN SCOPE", width)
        ],
        *_color_wrapped(
            score_text,
            content_width,
            indent="  ",
            status=score_status,
            bold=True,
        ),
    ]

    if score.unscored_verified:
        lines.extend(_wrap(
            f"Verified FAIL findings not scored: {score.unscored_verified}.",
            content_width,
            indent="  ",
        ))

    coverage_text = "LIMITED" if limited else "COMPLETE"
    coverage_status = "REVIEW" if limited else "PASS"
    lines.extend(_color_wrapped(
        f"Coverage: {coverage_text}",
        content_width,
        indent="  ",
        status=coverage_status,
        bold=True,
    ))
    if limited:
        lines.extend(_wrap(
            "Incomplete checks and review items are not converted into risk scores "
            "or treated as proof of safety.",
            content_width,
            indent="  ",
        ))

    lines.extend(_wrap(
        "Method: maximum eligible Impact × qualitative Probability score; "
        "finding scores are not summed.",
        content_width,
        indent="  ",
    ))
    return lines


def _render_compact_scan_report(report: ScanReport, width: int) -> list[str]:
    """Render a human-readable summary while retaining actionable outcomes."""
    width = max(1, width)
    content_width = max(1, width - 2)
    summary = build_assessment_summary(
        findings=report.findings,
        coverage=report.coverage,
        review_items=report.review_items,
    )

    statuses = [
        _finding_status(finding)
        for finding in report.findings
    ]
    counts = {
        status: statuses.count(status)
        for status in ("FAIL", "REVIEW", "NOT_ASSESSED", "ERROR")
    }
    actionable = [
        finding for finding in report.findings
        if _finding_status(finding) != "PASS"
    ]
    priority = {"FAIL": 0, "ERROR": 1, "REVIEW": 2, "NOT_ASSESSED": 3}
    actionable.sort(
        key=lambda finding: priority.get(_finding_status(finding), 4)
    )

    coverage = getattr(report.coverage, "value", report.coverage)
    lines = [
        accent("ASSESSMENT SUMMARY", bold=True),
        *_wrap(f"Host: {_compact_host_identity(report)}", content_width, indent="  "),
        *_wrap(
            f"Coverage: {coverage} · Review items: {report.review_items}",
            content_width,
            indent="  ",
        ),
    ]

    count_parts = [
        f"{counts['FAIL']} verified",
        f"{counts['REVIEW']} review",
        f"{counts['NOT_ASSESSED']} not assessed",
        f"{counts['ERROR']} errors",
    ]
    lines.extend(_wrap(
        "Findings: " + " · ".join(count_parts),
        content_width,
        indent="  ",
    ))

    lines.extend(("", accent(f"ATTENTION · {len(actionable)}", bold=True)))
    if not actionable:
        if report.coverage is AssessmentCoverage.PARTIAL or report.review_items:
            lines.extend(_wrap(
                "No non-passing findings were emitted, but some checks may be incomplete.",
                content_width,
                indent="  ",
            ))
        else:
            lines.append("  No non-passing findings reported.")
    else:
        visible = actionable[:5]
        for finding in visible:
            status = _finding_status(finding)
            lines.extend(_color_wrapped(
                f"[{status}] {_compact_finding_title(finding)}",
                content_width,
                indent="  ",
                status=status,
            ))
        omitted = len(actionable) - len(visible)
        if omitted:
            lines.extend(_wrap(
                f"{omitted} additional finding(s) omitted; use --details for the full list.",
                content_width,
                indent="  ",
            ))

    sections = list(report.sections)
    has_system = any(
        section.title in {"SYSTEM", "HOST", "HOST DETAILS"}
        for section in sections
    )
    if report.host is not None and not has_system:
        host = report.host
        distribution = host.distribution or "Unavailable"
        if host.distribution_version:
            distribution += f" ({host.distribution_version})"
        system_facts = (
            ("Hostname", host.hostname or "Unavailable"),
            ("Distribution", distribution),
            ("Kernel", host.kernel_release or "Unavailable"),
            ("Architecture", host.architecture or "Unavailable"),
            ("Uptime", _uptime(host.uptime_seconds)),
        )
        sections.insert(0, ReportSection("SYSTEM", facts=system_facts))

    if sections:
        lines.extend(("", accent("AREA SUMMARY", bold=True)))
        for section in sections:
            lines.append("")
            lines.extend(_compact_section_lines(section, width))

    lines.extend(("", accent("FINAL RESULT", bold=True)))
    icon = {
        "NO VERIFIED ISSUES": "✓",
        "REVIEW REQUIRED": "⚠",
        "ISSUES DETECTED": "✗",
    }.get(summary.result.value, "!")
    lines.append(_status_color(f"  {icon} {summary.result.value}", _normalize_status(summary.result.value), bold=True))
    lines.extend(_host_risk_summary_lines(report, width))
    result_status = _normalize_status(summary.result.value)
    lines.extend(_wrap(summary.description, content_width, indent="  "))
    _append_final_finding_summary(lines, report, width)

    if report.privilege is not None:
        lines.extend(_wrap(
            f"Execution mode: {report.privilege.mode} (UID {report.privilege.uid})",
            content_width,
            indent="  ",
        ))
        if (
            not report.privilege.privileged
            and report.coverage is AssessmentCoverage.PARTIAL
        ):
            lines.extend(_wrap(
                "Some checks could not be completed with the current privileges.",
                content_width,
                indent="  ",
            ))
            lines.extend(_wrap(
                "Use elevated privileges to complete checks that need them: sudo vulpnix",
                content_width,
                indent="  ",
            ))

    if summary.action:
        lines.extend(_wrap(
            f"Next step: {summary.action}",
            content_width,
            indent="  ",
        ))

    return lines


def render_scan_report(report: ScanReport, width: int) -> list[str]:
    """Render a scan report, adapting cards and wrapped text to terminal width."""
    width = max(1, width)
    if not report.details:
        return _render_compact_scan_report(report, width)
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

    risk_assessment = report.risk_assessment or assess_findings(report.findings)
    lines.extend(_risk_assessment_lines(
        risk_assessment, width, details=report.details
    ))

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
    lines.append(_status_color(f"  {icon} {summary.result.value}", _normalize_status(summary.result.value), bold=True))
    lines.extend(_host_risk_summary_lines(report, width))
    if report.privilege is not None:
        mode = report.privilege.mode
        lines.extend(_wrap(f"  Execution mode: {mode} (UID {report.privilege.uid})", width - 2))
    result_status = _normalize_status(summary.result.value)
    lines.extend(_wrap(summary.description, width - 2, indent="  "))
    _append_final_finding_summary(lines, report, width)
    lines.extend(_wrap(summary.action, width - 2, indent="  "))
    if (
        report.privilege is not None
        and not report.privilege.privileged
        and report.coverage is AssessmentCoverage.PARTIAL
    ):
        lines.extend(_wrap("Some checks could not be completed with the current privileges.", width - 2, indent="  "))
        lines.extend(_wrap("Use elevated privileges to complete checks that need them: sudo vulpnix", width - 2, indent="  "))

    return lines
