"""Markdown and JSON security report exporters for Vulpnix."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import re

from vulpnix.cli.html_report import _report_destination
from vulpnix.cli.report import ScanReport
from vulpnix.cli.summary import AssessmentCoverage, build_assessment_summary
from vulpnix.risk.engine import assess_findings, assess_host_risk


_STATUS_ORDER = ("FAIL", "REVIEW", "NOT_ASSESSED", "ERROR", "PASS")


def _value(value: object) -> object:
    return getattr(value, "value", value)


def _text(value: object) -> str:
    return str(_value(value) if value is not None else "")


def _timestamp(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now().astimezone()
    return value.astimezone()


def _report_data(
    report: ScanReport,
    generated_at: datetime | None = None,
) -> dict[str, object]:
    """Build the shared normalized data model for Markdown and JSON."""
    timestamp = _timestamp(generated_at)
    risk_assessment = report.risk_assessment or assess_findings(report.findings)
    host_score = assess_host_risk(risk_assessment)
    summary = build_assessment_summary(
        findings=report.findings,
        coverage=report.coverage,
        review_items=report.review_items,
    )

    statuses = [_text(getattr(finding, "status", "REVIEW")).upper()
                for finding in report.findings]
    counts = {status: statuses.count(status) for status in _STATUS_ORDER}
    needs_review = sum(
        counts.get(status, 0)
        for status in ("REVIEW", "NOT_ASSESSED", "ERROR")
    )
    limited = (
        report.coverage is AssessmentCoverage.PARTIAL
        or report.review_items > 0
        or needs_review > 0
        or host_score.unscored_verified > 0
    )

    level = _text(host_score.level).upper() or "NO ELIGIBLE SCORE"
    risk_by_rule = {
        item.rule_id: item for item in risk_assessment.scored
    }
    unscored_rules = {
        item.rule_id for item in risk_assessment.unscored_verified
    }

    host = report.host
    host_data = None
    if host is not None:
        host_data = {
            "hostname": host.hostname,
            "distribution": host.distribution,
            "distribution_version": host.distribution_version,
            "kernel_release": host.kernel_release,
            "architecture": host.architecture,
            "uptime_seconds": host.uptime_seconds,
        }

    findings: list[dict[str, object]] = []
    for finding in report.findings:
        rule_id = str(getattr(finding, "rule_id", ""))
        scored = risk_by_rule.get(rule_id)
        finding_risk = None
        if scored is not None:
            finding_risk = {
                "level": _text(scored.level),
                "score": int(scored.score),
                "maximum_score": 25,
            }
        elif (
            _text(getattr(finding, "status", "")).upper() == "FAIL"
            and rule_id in unscored_rules
        ):
            finding_risk = {
                "level": "NOT_ASSESSED",
                "score": None,
                "maximum_score": 25,
            }

        cves: list[dict[str, object]] = []
        for cve in getattr(finding, "cves", ()) or ():
            scores = []
            for score in getattr(cve, "cvss", ()) or ():
                scores.append({
                    "version": _text(getattr(score, "version", None)),
                    "base_score": getattr(score, "base_score", None),
                    "severity": _text(getattr(score, "severity", None)),
                    "vector": getattr(score, "vector", None),
                    "source": getattr(score, "source", None),
                })
            cves.append({
                "cve_id": getattr(cve, "cve_id", ""),
                "cvss": scores,
            })

        findings.append({
            "rule_id": rule_id,
            "title": getattr(finding, "title", ""),
            "status": _text(getattr(finding, "status", "REVIEW")).upper(),
            "severity": _text(getattr(finding, "severity", None)) or None,
            "evidence": getattr(finding, "evidence", ""),
            "explanation": getattr(finding, "explanation", ""),
            "recommendation": getattr(finding, "recommendation", ""),
            "impact": getattr(finding, "impact", None),
            "probability": getattr(finding, "probability", None),
            "risk_rationale": getattr(finding, "risk_rationale", None),
            "risk": finding_risk,
            "cves": cves,
        })

    sections: list[dict[str, object]] = []
    for section in report.sections:
        blocks = []
        for block in section.blocks:
            blocks.append({
                "title": block.title,
                "lines": list(block.lines),
                "lists": [
                    {"label": label, "items": list(items)}
                    for label, items in block.lists
                ],
            })
        sections.append({
            "title": section.title,
            "status": _text(section.status) or None,
            "message": section.message,
            "facts": [
                {"label": label, "value": value}
                for label, value in section.facts
            ],
            "table": [
                {"label": label, "value": value}
                for label, value in section.table
            ],
            "items_label": section.items_label,
            "items": list(section.items),
            "blocks": blocks,
            "footer": section.footer,
        })

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

    return {
        "schema_version": "1.0",
        "tool": "Vulpnix",
        "generated_at": timestamp.isoformat(timespec="seconds"),
        "result": {
            "status": summary.result.value,
            "description": summary.description,
            "recommended_action": summary.action,
        },
        "host": host_data,
        "scope": list(report.scope),
        "coverage": {
            "observed": _text(report.coverage),
            "status": "LIMITED" if limited else "COMPLETE",
            "is_limited": limited,
            "findings": counts,
            "findings_to_review": needs_review,
            "additional_review_items": max(0, int(report.review_items)),
            "total_review_items": summary.review_items,
        },
        "risk": {
            "score": int(host_score.score),
            "maximum_score": 25,
            "level": level,
            "unscored_verified_findings": int(host_score.unscored_verified),
            "note": score_note,
        },
        "privilege": (
            {
                "mode": report.privilege.mode,
                "uid": report.privilege.uid,
            }
            if report.privilege is not None
            else None
        ),
        "details": bool(report.details),
        "findings": findings,
        "sections": sections,
        "methodology": {
            "risk_score": (
                "Maximum eligible individual Impact × qualitative Probability "
                "score; finding scores are not summed."
            ),
            "limitations": (
                "REVIEW, NOT_ASSESSED and ERROR are not confirmed vulnerabilities. "
                "Incomplete coverage is not proof of safety."
            ),
        },
    }


def _md(value: object) -> str:
    """Escape dynamic text so scan data cannot create Markdown structure."""
    text = str(value if value is not None else "")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for character in ("\\", "`", "*", "_", "[", "]", "|"):
        text = text.replace(character, "\\" + character)
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "<br>")


def _md_code(value: object) -> str:
    text = str(value if value is not None else "").replace("`", "\\`")
    return "`" + text.replace("\n", " ") + "`"


def render_markdown_report(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a readable Markdown report from the normalized report data."""
    data = _report_data(report, generated_at)
    result = data["result"]
    coverage = data["coverage"]
    risk = data["risk"]
    host = data["host"]

    lines = [
        "# Vulpnix Security Report",
        "",
        f"- **Generated:** {_md(data['generated_at'])}",
        f"- **Result:** {_md(result['status'])}",
        f"- **Coverage:** {_md(coverage['status'])} "
        f"(observed: {_md(coverage['observed'])})",
        f"- **Host risk score:** {_md(risk['score'])}/25 — {_md(risk['level'])}",
        "",
        "## Host",
        "",
    ]

    if host is None:
        lines.append("Host facts were not collected for this scan.")
    else:
        for key, label in (
            ("hostname", "Hostname"),
            ("distribution", "Distribution"),
            ("distribution_version", "Distribution version"),
            ("kernel_release", "Kernel"),
            ("architecture", "Architecture"),
            ("uptime_seconds", "Uptime (seconds)"),
        ):
            value = host.get(key)
            if value is not None:
                lines.append(f"- **{label}:** {_md(value)}")

    lines.extend(["", "## Assessment overview", ""])
    lines.append(_md(result["description"]))
    lines.extend(["", _md(result["recommended_action"]), ""])
    lines.extend([
        "| Metric | Value |",
        "|---|---:|",
        f"| Verified findings | {coverage['findings'].get('FAIL', 0)} |",
        f"| Findings to review | {coverage['findings_to_review']} |",
        f"| Additional review items | {coverage['additional_review_items']} |",
        f"| Total findings | {len(data['findings'])} |",
        "",
        "## Scope",
        "",
    ])

    if data["scope"]:
        lines.extend(f"- {_md(item)}" for item in data["scope"])
    else:
        lines.append("No scope details recorded.")

    lines.extend(["", "## Findings", ""])
    if not data["findings"]:
        lines.append("No findings were emitted by the recorded checks.")
    else:
        for status in _STATUS_ORDER:
            group = [
                finding for finding in data["findings"]
                if finding["status"] == status
            ]
            if not group:
                continue
            lines.extend([f"### {status}", ""])
            for finding in group:
                lines.extend([
                    f"#### {_md(finding['title'])}",
                    "",
                    f"- **Rule:** {_md(finding['rule_id'])}",
                    f"- **Status:** {_md(finding['status'])}",
                ])
                if finding["severity"]:
                    lines.append(f"- **Severity:** {_md(finding['severity'])}")
                if finding["risk"]:
                    score = finding["risk"]["score"]
                    score_text = (
                        "unscored"
                        if score is None
                        else f"{score}/25"
                    )
                    lines.append(
                        f"- **Risk:** {_md(finding['risk']['level'])} "
                        f"({score_text})"
                    )
                if finding["impact"] is not None:
                    lines.append(f"- **Impact:** {_md(finding['impact'])}/5")
                if finding["probability"] is not None:
                    lines.append(
                        f"- **Probability:** {_md(finding['probability'])}/5"
                    )
                lines.extend([
                    "",
                    "**Evidence**",
                    "",
                    _md(finding["evidence"]),
                    "",
                    "**Why it matters**",
                    "",
                    _md(finding["explanation"]),
                    "",
                    "**Recommended action**",
                    "",
                    _md(finding["recommendation"]),
                ])
                if finding["risk_rationale"]:
                    lines.extend([
                        "",
                        "**Risk rationale**",
                        "",
                        _md(finding["risk_rationale"]),
                    ])
                for cve in finding["cves"]:
                    lines.extend(["", f"**CVE:** {_md(cve['cve_id'])}"])
                    if not cve["cvss"]:
                        lines.append("- CVSS unavailable")
                    for score in cve["cvss"]:
                        lines.append(
                            f"- **CVSS { _md(score['version']) }:** "
                            f"{_md(score['base_score'])} "
                            f"({_md(score['severity'])})"
                        )
                        if score["source"]:
                            lines.append(f"  - **Source:** {_md(score['source'])}")
                        if score["vector"]:
                            lines.append(f"  - **Vector:** {_md_code(score['vector'])}")
                lines.append("")

    lines.extend(["## Area analysis", ""])
    if not data["sections"]:
        lines.append("No area-specific sections were recorded.")
    else:
        for section in data["sections"]:
            title = _md(section["title"])
            if section["status"]:
                title += f" — {_md(section['status'])}"
            lines.extend([f"### {title}", ""])
            if section["message"]:
                lines.extend([_md(section["message"]), ""])
            for label, entries in (
                ("Facts", section["facts"]),
                ("Table", section["table"]),
            ):
                if entries:
                    lines.extend([
                        f"**{label}**",
                        "",
                        "| Field | Value |",
                        "|---|---|",
                    ])
                    lines.extend(
                        f"| {_md(item['label'])} | {_md(item['value'])} |"
                        for item in entries
                    )
                    lines.append("")
            if section["items_label"]:
                lines.extend([f"**{_md(section['items_label'])}**", ""])
            for item in section["items"]:
                lines.append(f"- {_md(item)}")
            if section["items"]:
                lines.append("")
            for block in section["blocks"]:
                lines.extend([f"#### {_md(block['title'])}", ""])
                for item in block["lines"]:
                    lines.append(f"- {_md(item)}")
                for named_list in block["lists"]:
                    lines.extend([f"**{_md(named_list['label'])}**", ""])
                    lines.extend(f"- {_md(item)}" for item in named_list["items"])
                lines.append("")
            if section["footer"]:
                lines.extend([_md(section["footer"]), ""])
    lines.extend([
        "## Methodology and limitations",
        "",
        _md(risk["note"]),
        "",
        _md(data["methodology"]["risk_score"]),
        "",
        _md(data["methodology"]["limitations"]),
        "",
    ])
    return "\n".join(lines)


def render_json_report(
    report: ScanReport,
    *,
    generated_at: datetime | None = None,
) -> str:
    """Render a stable, machine-readable JSON report."""
    return json.dumps(
        _report_data(report, generated_at),
        ensure_ascii=False,
        indent=2,
    ) + "\n"


def save_report_export(
    report: ScanReport,
    output_format: str,
    *,
    area: str | None = None,
    home: Path | None = None,
    generated_at: datetime | None = None,
) -> Path:
    """Save Markdown or JSON into the private report directory without overwriting."""
    renderers = {
        "markdown": ("md", render_markdown_report),
        "json": ("json", render_json_report),
    }
    selected = renderers.get(output_format)
    if selected is None:
        raise ValueError(f"Unsupported export format: {output_format}")

    extension, renderer = selected
    timestamp = _timestamp(generated_at)
    document = renderer(report, generated_at=timestamp)

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

    if created_directory and os.geteuid() == 0:
        os.chown(reports_dir, owner_uid, owner_gid)

    directory_info = reports_dir.stat()
    if directory_info.st_uid != owner_uid:
        raise PermissionError(
            f"Report directory is not owned by the report user: {reports_dir}"
        )
    os.chmod(reports_dir, 0o700)

    timestamp_text = timestamp.strftime("%Y%m%d_%H%M%S")
    slug = re.sub(r"[^a-z0-9]+", "-", (area or "").lower()).strip("-")
    prefix = "report_scan"
    if slug:
        prefix += f"_{slug}"
    prefix += f"_{timestamp_text}"

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)

    for suffix in range(10000):
        numbered = "" if suffix == 0 else f"_{suffix:02d}"
        destination = reports_dir / f"{prefix}{numbered}.{extension}"
        try:
            descriptor = os.open(destination, flags, 0o600)
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
