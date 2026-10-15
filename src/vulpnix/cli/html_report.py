"""Self-contained HTML security report renderer for Vulpnix."""

from __future__ import annotations

from base64 import b64encode
from datetime import datetime
from html import escape
from importlib.resources import files
import math
import os
from pathlib import Path
import pwd
import re

from vulpnix.cli.report import ScanReport, _fact_status, _line_status
from vulpnix.cli.summary import AssessmentCoverage, build_assessment_summary
from vulpnix.risk.engine import assess_findings, assess_host_risk


_STATUS_CLASSES = {
    "PASS": "pass",
    "LOW": "pass",
    "NO VERIFIED ISSUES": "pass",
    "FAIL": "fail",
    "ISSUES DETECTED": "fail",
    "ERROR": "error",
    "CRITICAL": "error",
    "HIGH": "high",
    "MODERATE": "review",
    "REVIEW": "review",
    "REVIEW REQUIRED": "review",
    "NOT_ASSESSED": "not-assessed",
    "NOT ASSESSED": "not-assessed",
    "PARTIAL": "review",
    "COMPLETE": "pass",
}

_STATUS_ORDER = (
    ("FAIL", "Verified issues"),
    ("REVIEW", "Needs review"),
    ("NOT_ASSESSED", "Not assessed"),
    ("ERROR", "Collection errors"),
    ("PASS", "Passed checks"),
)

_GAUGE_RADIUS = 59
_GAUGE_CIRCUMFERENCE = 2 * math.pi * _GAUGE_RADIUS


def _e(value: object) -> str:
    """Escape dynamic content for safe insertion into HTML text and attributes."""
    return escape(str(value if value is not None else ""), quote=True)


def _enum_text(value: object) -> str:
    return str(getattr(value, "value", value) or "")


def _status_class(status: object) -> str:
    value = _enum_text(status).strip().upper()
    return _STATUS_CLASSES.get(value, "neutral")


def _finding_status(finding: object) -> str:
    return _enum_text(getattr(finding, "status", "REVIEW")).upper() or "REVIEW"


def _asset_data_uri(name: str) -> str:
    """Read a packaged PNG and embed it, keeping the report portable."""
    try:
        data = files("vulpnix.cli").joinpath("assets", name).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError, TypeError):
        return ""
    return "data:image/png;base64," + b64encode(data).decode("ascii")


def _status_badge(label: object, status: object) -> str:
    css = _status_class(status)
    return (
        f'<span class="status-pill status-pill--{css}">'
        f"{_e(label)}</span>"
    )


def _render_fact(label: object, value: object) -> str:
    status = _fact_status(str(label), value)
    css = f" status-value--{_status_class(status)}" if status else ""
    return (
        '<div class="fact-row">'
        f'<dt class="fact-label">{_e(label)}</dt>'
        f'<dd class="fact-value{css}">{_e(value)}</dd>'
        "</div>"
    )


def _render_lines(items: tuple[str, ...] | list[str]) -> str:
    rendered = []
    for item in items:
        status = _line_status(item)
        css = f" status-value--{_status_class(status)}" if status else ""
        rendered.append(f'<li class="report-line{css}">{_e(item)}</li>')
    return "<ul class=\"report-list\">" + "".join(rendered) + "</ul>" if rendered else ""


def _render_block(block: object) -> str:
    parts = [f'<div class="detail-block"><h4>{_e(block.title)}</h4>']
    parts.append(_render_lines(block.lines))
    for label, items in block.lists:
        parts.append(f'<h5>{_e(label)}</h5>')
        parts.append(_render_lines(items) if items else '<p class="muted">None identified.</p>')
    parts.append("</div>")
    return "".join(parts)


def _render_section(section: object, index: int) -> str:
    """Render an area with neutral headings and semantically styled values."""
    total = (
        len(section.facts)
        + len(section.table)
        + len(section.items)
        + sum(len(block.lines) for block in section.blocks)
    )
    status_badge = (
        _status_badge(section.status, section.status)
        if section.status
        else ""
    )

    parts = [
        f'<details class="area-card" id="area-{index}">',
        "<summary>",
        f'<span class="area-title">{_e(section.title)}</span>',
        '<span class="area-summary-meta">',
        f'<span>{total} records</span>',
        status_badge,
        "</span>",
        "</summary>",
        '<div class="area-content">',
    ]

    if section.message:
        parts.append(f'<p class="section-message">{_e(section.message)}</p>')

    if section.facts:
        parts.append('<dl class="facts-grid">')
        parts.extend(_render_fact(label, value) for label, value in section.facts)
        parts.append("</dl>")

    if section.table:
        parts.append(
            '<div class="table-wrap"><table><thead><tr>'
            "<th>Option</th><th>Value</th>"
            "</tr></thead><tbody>"
        )
        for label, value in section.table:
            status = _fact_status(label, value)
            css = f" status-value--{_status_class(status)}" if status else ""
            parts.append(
                "<tr>"
                f"<th scope=\"row\">{_e(label)}</th>"
                f'<td class="fact-value{css}">{_e(value)}</td>'
                "</tr>"
            )
        parts.append("</tbody></table></div>")

    if section.items_label:
        parts.append(f'<h4>{_e(section.items_label)}</h4>')
    parts.append(_render_lines(section.items))

    for block in section.blocks:
        parts.append(_render_block(block))

    if section.footer:
        parts.append(f'<p class="section-footer">{_e(section.footer)}</p>')

    if total == 0 and not section.message and not section.footer:
        parts.append('<p class="muted">No additional details were recorded.</p>')

    parts.append("</div></details>")
    return "".join(parts)


def _render_finding(
    finding: object,
    risk_by_rule: dict[str, object],
    unscored_rules: set[str],
) -> str:
    status = _finding_status(finding)
    css = _status_class(status)
    rule_id = str(getattr(finding, "rule_id", ""))
    risk = risk_by_rule.get(rule_id)

    risk_markup = ""
    if risk is not None:
        level = _enum_text(risk.level)
        risk_markup = (
            f'<span class="risk-chip risk-chip--{_status_class(level)}">'
            f'{_e(level)} · {int(risk.score)}/25</span>'
        )
    elif status == "FAIL" and rule_id in unscored_rules:
        risk_markup = _status_badge(
            "Risk profile incomplete",
            "NOT_ASSESSED",
        )

    severity = getattr(finding, "severity", None)
    severity_markup = (
        f'<span class="severity-label">{_e(_enum_text(severity))}</span>'
        if severity is not None
        else ""
    )

    parts = [
        f'<article class="finding-card finding-card--{css}">',
        '<div class="finding-heading">',
        _status_badge(status, status),
        f'<h4>{_e(getattr(finding, "title", "Untitled finding"))}</h4>',
        "</div>",
        '<div class="finding-meta">',
        f'<span class="rule-id">{_e(rule_id)}</span>',
        severity_markup,
        risk_markup,
        "</div>",
        '<details class="finding-details"><summary>Evidence, explanation and recommendation</summary>',
        '<div class="finding-body">',
    ]

    evidence = getattr(finding, "evidence", None)
    explanation = getattr(finding, "explanation", None)
    recommendation = getattr(finding, "recommendation", None)
    rationale = getattr(finding, "risk_rationale", None)

    if evidence:
        parts.append(f'<h5>Evidence</h5><p>{_e(evidence)}</p>')
    if explanation:
        parts.append(f'<h5>Why it matters</h5><p>{_e(explanation)}</p>')
    if recommendation:
        parts.append(
            f'<div class="recommendation"><h5>Recommended action</h5>'
            f'<p>{_e(recommendation)}</p></div>'
        )
    if rationale:
        parts.append(f'<h5>Risk rationale</h5><p>{_e(rationale)}</p>')

    impact = getattr(finding, "impact", None)
    probability = getattr(finding, "probability", None)
    if impact is not None and probability is not None:
        parts.append(
            f'<p class="muted">Risk profile: Impact {int(impact)}/5 × '
            f'Probability {int(probability)}/5.</p>'
        )

    parts.extend(["</div></details>", "</article>"])
    return "".join(parts)


def _render_findings(report: ScanReport, risk_assessment: object) -> str:
    grouped: dict[str, list[object]] = {status: [] for status, _ in _STATUS_ORDER}
    for finding in report.findings:
        status = _finding_status(finding)
        grouped.setdefault(status, []).append(finding)

    risk_by_rule = {item.rule_id: item for item in risk_assessment.scored}
    unscored_rules = {
        item.rule_id for item in risk_assessment.unscored_verified
    }

    parts = ['<section class="panel findings-panel" id="findings">']
    parts.append(
        '<div class="panel-heading"><div><p class="eyebrow">ASSESSMENT DETAIL</p>'
        '<h2>Findings</h2></div>'
        f'<span class="panel-count">{len(report.findings)}</span></div>'
    )

    if not report.findings:
        parts.append(
            '<p class="empty-state">No findings were emitted by the recorded checks. '
            'This result does not make claims beyond the scan scope and coverage.</p>'
        )
    else:
        first_group = True
        for status, title in _STATUS_ORDER:
            findings = grouped.get(status, [])
            if not findings:
                continue

            open_attr = " open" if first_group else ""
            first_group = False
            parts.append(
                f'<details class="finding-group"{open_attr}>'
                '<summary>'
                f'<span>{_e(title)}</span>'
                f'<span class="group-count">{len(findings)}</span>'
                "</summary><div class=\"finding-group-content\">"
            )
            parts.extend(
                _render_finding(finding, risk_by_rule, unscored_rules)
                for finding in findings
            )
            parts.append("</div></details>")

    parts.append("</section>")
    return "".join(parts)


def render_html_report(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render one ScanReport as a self-contained, accessible HTML document."""
    risk_assessment = report.risk_assessment or assess_findings(report.findings)
    host_score = assess_host_risk(risk_assessment)
    summary = build_assessment_summary(
        findings=report.findings,
        coverage=report.coverage,
        review_items=report.review_items,
    )

    incomplete_findings = any(
        _finding_status(finding) in {"REVIEW", "NOT_ASSESSED", "ERROR"}
        for finding in report.findings
    )
    limited = (
        report.coverage is AssessmentCoverage.PARTIAL
        or report.review_items > 0
        or incomplete_findings
        or host_score.unscored_verified > 0
    )
    coverage_label = "LIMITED" if limited else "COMPLETE"
    coverage_status = "REVIEW" if limited else "PASS"

    level = _enum_text(host_score.level).upper() if host_score.level else ""
    if level in {"LOW", "MODERATE", "HIGH", "CRITICAL"}:
        gauge_class = level.lower()
    else:
        # A zero score without eligible findings is not presented as "low risk".
        gauge_class = "limited" if limited else "unscored"

    score_value = max(0, min(25, int(host_score.score)))
    circumference = _GAUGE_CIRCUMFERENCE
    offset = circumference * (1 - score_value / 25)
    result_class = _status_class(summary.result.value)

    counts = {
        status: sum(_finding_status(item) == status for item in report.findings)
        for status, _ in _STATUS_ORDER
    }
    needs_review = (
        counts.get("REVIEW", 0)
        + counts.get("NOT_ASSESSED", 0)
        + counts.get("ERROR", 0)
    )

    host = report.host
    hostname = getattr(host, "hostname", None) if host else None
    distribution = getattr(host, "distribution", None) if host else None
    distribution_version = getattr(host, "distribution_version", None) if host else None
    kernel = getattr(host, "kernel_release", None) if host else None

    host_label = str(hostname or "Host details unavailable")
    distro_label = str(distribution or "Distribution unavailable")
    if distribution_version:
        distro_label += f" ({distribution_version})"

    if generated_at is None:
        timestamp = datetime.now().astimezone()
    elif generated_at.tzinfo is None:
        timestamp = generated_at.astimezone()
    else:
        timestamp = generated_at.astimezone()
    generated_label = timestamp.strftime("%Y-%m-%d %H:%M:%S %Z").strip()

    logo_uri = _asset_data_uri("vulpnix_logo.png")
    full_logo_uri = _asset_data_uri("vulpnix_logo_full.png")
    mascot_uri = _asset_data_uri("vulpnix.png")

    logo_markup = (
        f'<img class="brand-logo" src="{_e(logo_uri)}" alt="Vulpnix logo">'
        if logo_uri
        else '<span class="brand-wordmark">VULPNIX</span>'
    )
    mascot_markup = (
        f'<img class="mascot" src="{_e(mascot_uri)}" alt="Vulpnix fox mascot">'
        if mascot_uri
        else ""
    )
    favicon_markup = (
        f'<link rel="icon" type="image/png" href="{_e(full_logo_uri)}">'
        if full_logo_uri
        else ""
    )

    scope_markup = "".join(
        f'<span class="scope-tag">{_e(item)}</span>'
        for item in report.scope
    )
    score_level_label = level if level else "NO ELIGIBLE SCORE"
    if host_score.score == 0:
        score_note = (
            "0/25 means no eligible verified finding contributed to the score. "
            "It is not proof of zero risk."
        )
    else:
        score_note = (
            "Maximum eligible individual finding score. Individual finding scores "
            "are not summed."
        )

    coverage_note = (
        "Incomplete checks and review items are not converted into risk scores "
        "or treated as proof of safety."
        if limited
        else "The recorded checks completed without unresolved coverage items. "
             "This is not a guarantee that every possible vulnerability is absent."
    )

    risk_note = (
        f'<p class="score-explanation">{_e(score_note)}</p>'
    )
    if host_score.unscored_verified:
        risk_note += (
            '<p class="score-explanation">'
            f'Verified findings without a complete risk profile: '
            f'{host_score.unscored_verified}.</p>'
        )

    privilege_markup = ""
    if report.privilege is not None:
        privilege_markup = (
            '<div class="meta-item"><span>Execution mode</span>'
            f'<strong>{_e(report.privilege.mode)} '
            f'(UID {_e(report.privilege.uid)})</strong></div>'
        )

    sections_html = "".join(
        _render_section(section, index)
        for index, section in enumerate(report.sections, start=1)
    )

    css = """
:root {
  color-scheme: dark;
  --bg: #171821;
  --surface: #20222e;
  --surface-raised: #272a38;
  --border: #3a3d4e;
  --text: #f4f1f7;
  --muted: #b9b8c9;
  --quiet: #898b9e;
  --orange: #ffb347;
  --lilac: #c4b5fd;
  --green: #86efac;
  --red: #ff7080;
  --amber: #ffcd80;
  --high: #ff975f;
  --radius: 18px;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont,
    "Segoe UI", sans-serif;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; background: var(--bg); }
body {
  margin: 0; background: var(--bg); color: var(--text); line-height: 1.58;
  font-size: 15px; -webkit-font-smoothing: antialiased;
}
a { color: var(--lilac); }
button, summary { font: inherit; }
.page { width: min(1180px, calc(100% - 44px)); margin: 0 auto; }
.site-header {
  display: flex; align-items: center; justify-content: space-between; gap: 24px;
  padding: 27px 0; border-bottom: 1px solid var(--border);
}
.brand { display: flex; align-items: center; gap: 17px; min-width: 0; }
.brand-logo { display: block; width: 70px; height: 70px; object-fit: contain; }
.brand-wordmark { color: var(--orange); font-weight: 850; font-size: 1.25rem; letter-spacing: .14em; }
.brand-title { margin: 0; font-size: 1.16rem; letter-spacing: .12em; font-weight: 800; }
.brand-subtitle { margin: 3px 0 0; color: var(--muted); font-size: .78rem; letter-spacing: .12em; }
.brand-caption { margin: 3px 0 0; color: var(--quiet); font-size: .72rem; letter-spacing: .09em; }
.header-meta { text-align: right; color: var(--muted); font-size: .8rem; }
.header-meta strong { display: block; color: var(--text); font-weight: 650; }
.eyebrow {
  color: var(--orange); letter-spacing: .14em; font-size: .71rem;
  font-weight: 800; margin: 0 0 7px;
}
.hero {
  display: grid; grid-template-columns: minmax(0, 1.35fr) minmax(285px, .8fr);
  gap: 26px; align-items: stretch; margin-top: 28px;
}
.panel, .hero-copy, .gauge-panel {
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
}
.hero-copy { padding: clamp(23px, 4vw, 38px); position: relative; overflow: hidden; }
.hero-copy::before {
  content: ""; position: absolute; inset: 0 auto 0 0; width: 4px;
  background: var(--orange);
}
.result-heading { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }
h1 { font-size: clamp(1.55rem, 3.2vw, 2.2rem); line-height: 1.17; margin: 0; letter-spacing: -.035em; }
.result-pill, .status-pill, .risk-chip, .scope-tag {
  display: inline-flex; align-items: center; gap: 6px; border: 1px solid transparent;
  border-radius: 999px; padding: 4px 10px; font-size: .74rem; font-weight: 760;
  letter-spacing: .035em;
}
.status-pill--pass, .status-value--pass { color: var(--green); }
.status-pill--pass { background: #86efac14; border-color: #86efac42; }
.status-pill--fail, .status-pill--error, .status-value--fail, .status-value--error {
  color: var(--red);
}
.status-pill--fail, .status-pill--error { background: #ff708014; border-color: #ff708044; }
.status-pill--review, .status-value--review, .status-value--high { color: var(--amber); }
.status-pill--review { background: #ffcd8014; border-color: #ffcd8044; }
.status-pill--not-assessed, .status-value--not-assessed { color: #b1b4c5; }
.status-pill--neutral, .status-value--neutral { color: var(--muted); }
.status-value--high { color: var(--high); }
.hero-description { color: #e0deea; font-size: 1rem; max-width: 62ch; margin: 20px 0 0; }
.hero-next { border-top: 1px solid var(--border); margin-top: 23px; padding-top: 16px; }
.hero-next strong { color: var(--orange); display: block; font-size: .75rem; letter-spacing: .11em; margin-bottom: 5px; }
.hero-next p { margin: 0; color: var(--muted); }
.gauge-panel { padding: 22px 19px; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
.gauge-label { color: var(--muted); font-size: .75rem; font-weight: 780; letter-spacing: .12em; }
.gauge {
  width: min(100%, 238px); height: auto; margin: 10px 0 6px; overflow: visible;
}
.gauge-track { stroke: #3a3d4e; }
.gauge-progress {
  fill: none; stroke: var(--gauge-tone); stroke-width: 11; stroke-linecap: round;
  stroke-dasharray: var(--gauge-circumference);
  stroke-dashoffset: var(--gauge-circumference);
  animation: fill-gauge .95s cubic-bezier(.2,.7,.2,1) forwards;
}
.gauge--low { --gauge-tone: var(--green); }
.gauge--moderate, .gauge--limited { --gauge-tone: var(--amber); }
.gauge--high { --gauge-tone: var(--high); }
.gauge--critical { --gauge-tone: var(--red); }
.gauge--unscored { --gauge-tone: #a6aabd; }
.gauge-value { font-size: 27px; font-weight: 820; fill: var(--text); letter-spacing: -.04em; }
.gauge-caption { font-size: 8px; font-weight: 700; letter-spacing: .11em; fill: var(--muted); }
.gauge-level { margin: 0 0 6px; color: var(--gauge-tone, var(--muted)); font-size: .78rem; font-weight: 800; letter-spacing: .1em; }
.score-explanation { margin: 8px 0 0; color: var(--quiet); font-size: .74rem; max-width: 34ch; }
.coverage-line { margin-top: 13px; color: var(--muted); font-size: .84rem; }
.coverage-line strong { color: var(--amber); }
.coverage-line .status-pill--pass { color: var(--green); }
.coverage-note { max-width: 42ch; color: var(--quiet); font-size: .76rem; margin: 9px 0 0; }
.scope-line { display: flex; gap: 8px; flex-wrap: wrap; margin: 18px 0 0; }
.scope-tag { border-color: var(--border); color: var(--muted); background: #1718217a; font-weight: 580; letter-spacing: 0; }
.stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin: 18px 0 30px; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 19px 21px; }
.stat-label { color: var(--muted); font-size: .73rem; font-weight: 780; letter-spacing: .075em; text-transform: uppercase; }
.stat-value { display: block; font-size: clamp(1.65rem, 3vw, 2.05rem); font-weight: 820; line-height: 1.25; margin: 7px 0 4px; }
.stat-note { color: var(--quiet); font-size: .78rem; }
.stat--fail .stat-value { color: var(--red); }
.stat--review .stat-value { color: var(--amber); }
.stat--neutral .stat-value { color: var(--lilac); }
.panel { padding: clamp(19px, 3vw, 28px); margin: 20px 0; }
.panel-heading { display: flex; align-items: center; justify-content: space-between; gap: 20px; margin-bottom: 18px; }
h2 { font-size: 1.35rem; margin: 0; letter-spacing: -.02em; }
.panel-count, .group-count { border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px; color: var(--muted); font-size: .78rem; }
.finding-group, .area-card { border: 1px solid var(--border); border-radius: 13px; overflow: clip; margin-top: 10px; background: #1a1c26; }
.finding-group > summary, .area-card > summary {
  cursor: pointer; display: flex; justify-content: space-between; align-items: center;
  gap: 13px; padding: 15px 17px; list-style: none; font-weight: 750;
}
.finding-group > summary::-webkit-details-marker, .area-card > summary::-webkit-details-marker { display: none; }
.finding-group > summary::after, .area-card > summary::after { content: "+"; color: var(--quiet); font-size: 1.15rem; margin-left: auto; }
.finding-group[open] > summary::after, .area-card[open] > summary::after { content: "−"; }
.finding-group-content, .area-content { padding: 0 16px 16px; border-top: 1px solid var(--border); }
.finding-card { background: var(--surface-raised); border: 1px solid var(--border); border-left: 3px solid var(--quiet); border-radius: 12px; padding: 15px; margin-top: 13px; }
.finding-card--fail, .finding-card--error { border-left-color: var(--red); }
.finding-card--review, .finding-card--not-assessed { border-left-color: var(--amber); }
.finding-card--pass { border-left-color: var(--green); }
.finding-heading { display: flex; align-items: flex-start; flex-wrap: wrap; gap: 9px; }
.finding-heading h4 { flex: 1 1 270px; min-width: 0; margin: 3px 0; font-size: 1rem; line-height: 1.45; }
.finding-meta { display: flex; align-items: center; flex-wrap: wrap; gap: 7px; margin-top: 10px; }
.rule-id, .severity-label { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: .73rem; color: var(--muted); overflow-wrap: anywhere; }
.severity-label { border: 1px solid var(--border); border-radius: 6px; padding: 3px 7px; }
.risk-chip--pass { color: var(--green); background: #86efac14; }
.risk-chip--review { color: var(--amber); background: #ffcd8014; }
.risk-chip--high { color: var(--high); background: #ff975f14; }
.risk-chip--fail, .risk-chip--error { color: var(--red); background: #ff708014; }
.risk-chip--neutral, .risk-chip--not-assessed { color: var(--muted); background: #a6aabd12; }
.finding-details { margin-top: 13px; border-top: 1px solid var(--border); padding-top: 10px; }
.finding-details > summary { cursor: pointer; color: var(--lilac); font-size: .84rem; font-weight: 700; }
.finding-body { padding-top: 10px; }
.finding-body h5, .detail-block h5 { font-size: .78rem; color: var(--muted); letter-spacing: .06em; margin: 16px 0 5px; text-transform: uppercase; }
.finding-body p { margin: 0; overflow-wrap: anywhere; }
.recommendation { margin-top: 14px; border-left: 2px solid var(--orange); padding: 2px 0 2px 13px; }
.recommendation h5 { color: var(--orange); margin-top: 0; }
.empty-state { color: var(--muted); border: 1px dashed var(--border); border-radius: 12px; padding: 22px; }
.area-card { margin-top: 10px; }
.area-title { font-size: .96rem; }
.area-summary-meta { margin-left: auto; display: flex; align-items: center; flex-wrap: wrap; gap: 8px; color: var(--quiet); font-size: .75rem; font-weight: 500; }
.area-content { padding-top: 16px; }
.section-message, .section-footer { color: var(--muted); }
.facts-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1px 18px; margin: 0 0 17px; }
.fact-row { display: grid; grid-template-columns: minmax(120px, .9fr) minmax(0, 1.1fr); gap: 12px; align-items: start; padding: 10px 0; border-bottom: 1px solid #3a3d4e70; min-width: 0; }
.fact-label { color: var(--muted); overflow-wrap: anywhere; }
.fact-value { margin: 0; overflow-wrap: anywhere; min-width: 0; color: var(--text); }
.table-wrap { overflow-x: auto; margin: 14px 0; }
table { border-collapse: collapse; width: 100%; text-align: left; }
th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; overflow-wrap: anywhere; }
thead th { color: var(--muted); font-size: .73rem; text-transform: uppercase; letter-spacing: .08em; }
tbody th { color: var(--muted); font-weight: 600; }
.report-list { padding-left: 22px; margin: 9px 0; }
.report-list li { margin: 5px 0; overflow-wrap: anywhere; }
.detail-block { border-top: 1px solid var(--border); margin-top: 20px; padding-top: 12px; }
.detail-block h4 { font-size: .95rem; margin: 0; }
.muted { color: var(--quiet); font-size: .85rem; }
.method-panel { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.method-panel p { color: var(--muted); margin: 7px 0 0; }
.footer { border-top: 1px solid var(--border); color: var(--quiet); display: flex; justify-content: space-between; gap: 14px; flex-wrap: wrap; padding: 22px 0 30px; margin-top: 26px; font-size: .76rem; }
.footer strong { color: var(--muted); }
@keyframes fill-gauge { to { stroke-dashoffset: var(--gauge-offset); } }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { scroll-behavior: auto !important; animation: none !important; transition: none !important; }
  .gauge-progress { stroke-dashoffset: var(--gauge-offset); }
}
@media (max-width: 760px) {
  .page { width: min(100% - 26px, 600px); }
  .hero { grid-template-columns: 1fr; }
  .gauge-panel { display: grid; grid-template-columns: 1fr 1.3fr; text-align: left; gap: 4px 18px; }
  .gauge { grid-row: span 4; width: 100%; max-width: 180px; margin: 0; }
  .gauge-label, .gauge-level, .coverage-line, .coverage-note, .score-explanation { grid-column: 2; }
  .stats { grid-template-columns: 1fr; }
  .stat-card { padding: 15px 17px; }
  .facts-grid, .method-panel { grid-template-columns: 1fr; }
  .site-header { align-items: flex-start; }
  .brand-logo { width: 56px; height: 56px; }
  .header-meta { font-size: .72rem; }
}
@media (max-width: 440px) {
  .page { width: calc(100% - 20px); }
  .site-header { gap: 12px; padding: 19px 0; }
  .brand { gap: 10px; }
  .brand-logo { width: 44px; height: 44px; }
  .brand-subtitle { font-size: .66rem; }
  .brand-caption { font-size: .63rem; }
  .header-meta { max-width: 100px; overflow-wrap: anywhere; }
  .gauge-panel { grid-template-columns: 1fr; text-align: center; }
  .gauge { grid-row: auto; max-width: 178px; margin: 8px auto; }
  .gauge-label, .gauge-level, .coverage-line, .coverage-note, .score-explanation { grid-column: auto; }
  .area-summary-meta { justify-content: flex-end; }
  .fact-row { grid-template-columns: 1fr; gap: 3px; }
}
@media print {
  :root { color-scheme: light; --bg: #fff; --surface: #fff; --surface-raised: #f8f8fa; --border: #d1d3dc; --text: #191a22; --muted: #414354; --quiet: #616477; }
  body { background: #fff; color: #191a22; print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  .page { width: 100%; }
  .hero-copy, .panel, .gauge-panel, .stat-card, .finding-card, .finding-group, .area-card { break-inside: avoid; }
  details:not([open]) > :not(summary) { display: block !important; }
  details, .area-content, .finding-group-content { display: block !important; }
  .finding-details > summary { display: none; }
  .finding-details > .finding-body { display: block !important; }
  .footer { margin-top: 20px; }
}
"""

    gauge_svg = (
        '<svg class="gauge" viewBox="0 0 144 144" role="img" '
        f'aria-label="Observed host risk score {host_score.score} out of 25; '
        f'level {score_level_label}; coverage {coverage_label}">'
        '<circle class="gauge-track" cx="72" cy="72" r="59" '
        'fill="none" stroke-width="11"/>'
        f'<circle class="gauge-progress gauge--{_e(gauge_class)}" '
        'cx="72" cy="72" r="59" fill="none" stroke-width="11" '
        'stroke-linecap="round" transform="rotate(-90 72 72)" '
        f'style="--gauge-offset:{offset:.3f}px;'
        f'--gauge-circumference:{circumference:.3f}px"/>'
        f'<text class="gauge-value" x="72" y="68" text-anchor="middle">'
        f'{_e(host_score.score)}/25</text>'
        '<text class="gauge-caption" x="72" y="88" text-anchor="middle">'
        'OBSERVED SCORE</text></svg>'
    )

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
{favicon_markup}
<title>Vulpnix Security Report — {_e(host_label)}</title>
<style>{css}</style>
</head>
<body>
<div class="page">
  <header class="site-header">
    <div class="brand">
      {logo_markup}
      <div>
        <p class="brand-title">VULPNIX</p>
        <p class="brand-subtitle">LINUX HOST ASSESSMENT</p>
        <p class="brand-caption">SECURITY REPORT · LOCAL ANALYSIS</p>
      </div>
    </div>
    <div class="header-meta">
      <strong>Security assessment</strong>
      <span>Generated {_e(generated_label)}</span>
    </div>
  </header>

  <main>
    <section class="hero" aria-labelledby="report-title">
      <div class="hero-copy">
        <p class="eyebrow">HOST SECURITY ASSESSMENT</p>
        <div class="result-heading">
          <h1 id="report-title">{_e(summary.result.value)}</h1>
        </div>
        <p class="hero-description">{_e(summary.description)}</p>
        <div class="scope-line">
          <span class="scope-tag">{_e(host_label)}</span>
          <span class="scope-tag">{_e(distro_label)}</span>
          {''.join(f'<span class="scope-tag">{_e(item)}</span>' for item in report.scope)}
        </div>
        {mascot_markup}
        <div class="hero-next">
          <strong>NEXT STEP</strong>
          <p>{_e(summary.action)}</p>
        </div>
      </div>

      <aside class="gauge-panel" aria-label="Observed risk score and coverage">
        <div class="gauge-label">HOST RISK SCORE</div>
        {gauge_svg}
        <div class="gauge-level">{_e(score_level_label)}</div>
        {risk_note}
        <div class="coverage-line">
          Coverage: {_status_badge(coverage_label, coverage_status)}
        </div>
        <p class="coverage-note">{_e(coverage_note)}</p>
      </aside>
    </section>

    <section class="stats" aria-label="Assessment statistics">
      <div class="stat-card stat--fail">
        <div class="stat-label">Verified issues</div>
        <strong class="stat-value">{counts.get("FAIL", 0)}</strong>
        <div class="stat-note">Finding status: FAIL</div>
      </div>
      <div class="stat-card stat--review">
        <div class="stat-label">Findings to review</div>
        <strong class="stat-value">{needs_review}</strong>
        <div class="stat-note">Review, not assessed or error; not automatically confirmed vulnerabilities.</div>
      </div>
      <div class="stat-card stat--neutral">
        <div class="stat-label">Additional review items</div>
        <strong class="stat-value">{max(0, int(report.review_items))}</strong>
        <div class="stat-note">Additional coverage and review items recorded by the scan.</div>
      </div>
    </section>

    {_render_findings(report, risk_assessment)}

    <section class="panel" id="area-analysis">
      <div class="panel-heading">
        <div><p class="eyebrow">TECHNICAL DETAIL</p><h2>Area analysis</h2></div>
        <span class="panel-count">{len(report.sections)} areas</span>
      </div>
      {sections_html if sections_html else '<p class="empty-state">No area-specific sections were recorded.</p>'}
    </section>

    <section class="panel method-panel" id="methodology">
      <div>
        <p class="eyebrow">SCORING METHOD</p>
        <h2>How to read the score</h2>
        <p>Observed host risk score is the maximum eligible individual Impact × qualitative Probability score. Individual finding scores are not summed.</p>
        <p>{_e(score_note)}</p>
      </div>
      <div>
        <p class="eyebrow">COVERAGE AND LIMITATIONS</p>
        <h2>What this report establishes</h2>
        <p>{_e(coverage_note)}</p>
        <p>A finding marked REVIEW, NOT_ASSESSED or ERROR is not treated as a verified vulnerability or as evidence that the host is safe.</p>
      </div>
    </section>
  </main>

  <footer class="footer">
    <span><strong>VULPNIX</strong> · Linux host risk assessment</span>
    <span>Generated {_e(generated_label)}</span>
    <span>{_e(len(report.findings))} findings · {_e(len(report.sections))} areas</span>
    {privilege_markup}
    <span>Self-contained HTML · No external resources</span>
  </footer>
</div>
</body>
</html>
"""
    return html


def _report_destination(home: Path | None = None) -> tuple[Path, int, int]:
    """Resolve the report owner's home, including sudo-launched sessions."""
    if home is not None:
        return home.expanduser().resolve(), os.getuid(), os.getgid()

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            account = pwd.getpwnam(sudo_user)
        except KeyError as error:
            raise PermissionError(
                "Cannot resolve the original user home for report export."
            ) from error
        return Path(account.pw_dir), account.pw_uid, account.pw_gid

    return Path.home(), os.getuid(), os.getgid()


def save_html_report(
    report: ScanReport,
    *,
    area: str | None = None,
    home: Path | None = None,
    generated_at: datetime | None = None,
) -> Path:
    """Save a self-contained HTML report without overwriting existing files."""
    user_home, owner_uid, owner_gid = _report_destination(home)
    reports_dir = user_home / "vulpnix_reports"

    created_directory = False
    try:
        reports_dir.mkdir(mode=0o700)
        created_directory = True
    except FileExistsError:
        pass

    if reports_dir.is_symlink() or not reports_dir.is_dir():
        raise PermissionError(
            f"Report destination is not a safe directory: {reports_dir}"
        )

    # A directory created by sudo must belong to the original user.
    if created_directory and os.geteuid() == 0:
        os.chown(reports_dir, owner_uid, owner_gid)

    directory_info = reports_dir.stat()
    if directory_info.st_uid != owner_uid:
        raise PermissionError(
            f"Report directory is not owned by the report user: {reports_dir}"
        )

    # A dedicated report directory must not be accessible to other users.
    os.chmod(reports_dir, 0o700)

    timestamp = (generated_at or datetime.now().astimezone()).astimezone()
    timestamp_text = timestamp.strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^a-z0-9]+", "-", (area or "").lower()).strip("-")
    prefix = "report_scan"
    if slug:
        prefix += f"_{slug}"
    prefix += f"_{timestamp_text}"

    document = render_html_report(report, generated_at=timestamp)
    base_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    base_flags |= getattr(os, "O_NOFOLLOW", 0)

    for suffix in range(10000):
        numbered = "" if suffix == 0 else f"_{suffix:02d}"
        destination = reports_dir / f"{prefix}{numbered}.html"
        try:
            descriptor = os.open(
                destination,
                base_flags,
                0o600,
            )
        except FileExistsError:
            continue

        try:
            if os.geteuid() == 0:
                os.fchown(descriptor, owner_uid, owner_gid)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(
                descriptor,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as stream:
                stream.write(document)
            return destination
        except Exception:
            try:
                os.close(descriptor)
            except OSError:
                pass
            destination.unlink(missing_ok=True)
            raise

    raise FileExistsError("Could not allocate a unique Vulpnix report filename.")
