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

from vulpnix.cli.report import ReportBlock, ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.core import AreaResult, AreaStatus, FindingStatus
from vulpnix.models import SystemInfo
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


def _hardening_section(result: AreaResult, details: bool) -> ReportSection:
    """Counts, an attention list and (with details) every check, as before."""
    facts = result.facts
    passed = sum(fact.status is FindingStatus.PASS for fact in facts)
    failed = sum(fact.status is FindingStatus.FAIL for fact in facts)
    review = sum(fact.status is FindingStatus.REVIEW for fact in facts)
    unavailable = sum(
        fact.status in {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR} for fact in facts
    )
    unresolved = tuple(fact for fact in facts if fact.status is not FindingStatus.PASS)
    items = tuple(
        f"[{fact.status.value}] {fact.label}: {fact.value}" for fact in unresolved[:6]
    )
    if not items:
        items = ("All available hardening parameters matched the defined checks.",)
    elif len(unresolved) > len(items):
        remaining = len(unresolved) - len(items)
        if details:
            message = f"{remaining} additional check(s) are included in CHECK DETAILS."
        else:
            message = f"{remaining} additional check(s) omitted; use --details to list them."
        items += (message,)
    blocks = ()
    if details:
        lines = tuple(
            f"[{fact.status.value}] {fact.key}: observed={fact.value}; {fact.detail}"
            for fact in facts
        )
        blocks = (ReportBlock("CHECK DETAILS", lines=lines),)
    return ReportSection(
        title=result.title,
        facts=(
            ("Parameters checked", str(len(facts))),
            ("Checks passing", str(passed)),
            ("Verified concerns", str(failed)),
            ("Context review", str(review)),
            ("Unavailable/error", str(unavailable)),
        ),
        items=items,
        items_label="Items requiring attention:" if unresolved else "Assessment:",
        footer=" ".join(result.notes) or None,
        blocks=blocks,
    )


def _plural(count: int, singular: str = "account", plural: str = "accounts") -> str:
    return singular if count == 1 else plural


def _users_section(result: AreaResult, details: bool) -> ReportSection:
    """Assessment, review and details blocks, as the legacy users view showed them."""
    facts = {fact.key: fact for fact in result.facts}
    uid_zero = tuple(facts["uid0_accounts"].raw or ())
    additional = tuple(name for name in uid_zero if name != "root")
    privileged = tuple(facts["privileged_accounts"].raw or ())
    sudo_accounts = tuple(facts["sudo_accounts"].raw or ())
    sudo_without = tuple(facts["sudo_no_privileges"].raw or ())

    assessment: list[str] = []
    if not uid_zero:
        assessment.append("No UID 0 accounts detected")
    elif not additional:
        assessment.append("✓ Only one UID 0 account detected: root")
    else:
        assessment.append("Additional UID 0 accounts detected: " + ", ".join(additional))
    if privileged:
        assessment.append(
            f"✓ Privileged access verified for {len(privileged)} {_plural(len(privileged))}"
        )
    else:
        assessment.append("No privileged accounts verified")
    if sudo_accounts:
        assessment.append(
            f"✓ Sudo access verified for {len(sudo_accounts)} {_plural(len(sudo_accounts))}"
        )
    elif sudo_without:
        assessment.append(
            f"No sudo access verified for {len(sudo_without)} "
            f"inspected {_plural(len(sudo_without))}"
        )

    review: list[str] = []
    if additional:
        review.append(
            "Review authorization for additional UID 0 accounts: " + ", ".join(additional)
        )
    if any(gap.key.startswith("sudo_unavailable:") for gap in result.gaps):
        review.append("sudo is unavailable; sudo privileges could not be evaluated")
    causes: dict[str, int] = {}
    for gap in result.gaps:
        if gap.key.startswith("sudo_not_assessed:"):
            causes[gap.cause or gap.message] = causes.get(gap.cause or gap.message, 0) + 1
    for cause, count in causes.items():
        review.append(f"{count} {_plural(count)}: {cause}")
    state_unknown = sum(record.get("account_state") is None for record in result.records)
    if state_unknown:
        review.append(
            f"{state_unknown} {'account could' if state_unknown == 1 else 'accounts could'} "
            "not be evaluated for account state"
        )
    groups_unknown = sum(record.get("groups") is None for record in result.records)
    if groups_unknown:
        review.append(
            f"Group membership unavailable for {groups_unknown} {_plural(groups_unknown)}"
        )
    review.extend(gap.message for gap in result.gaps if gap.key == "sudo-collection-failed")
    if not review:
        review.append("No unresolved account information")

    if details:
        privilege_labels = {True: "yes", False: "no", None: "NOT_ASSESSED"}
        inventory = tuple(
            " · ".join((
                record.label,
                f"UID {record.get('uid')}",
                f"GID {record.get('gid')}",
                "groups: " + (
                    ", ".join(record.get("groups"))
                    if record.get("groups") is not None else "Unavailable"
                ),
                "shell: " + (record.get("shell") or "Unavailable"),
                "privileged: " + privilege_labels[record.get("privileged")],
                "account state: " + (record.get("account_state") or "NOT_ASSESSED"),
                record.get("sudo"),
            ))
            for record in result.records
        )
        detail_block = ReportBlock(
            title="ACCOUNT INVENTORY",
            lines=inventory or ("No local accounts found.",),
        )
    else:
        detail_block = ReportBlock(
            title="DETAILS",
            lists=(
                ("UID 0", uid_zero),
                ("Privileged", privileged),
                ("Sudo access", sudo_accounts),
            ),
        )
    return ReportSection(
        title=result.title,
        facts=(
            ("Local accounts", str(facts["local_accounts"].raw)),
            ("UID 0 accounts", str(len(uid_zero))),
            ("Privileged accounts", str(len(privileged))),
        ),
        blocks=(
            ReportBlock("ASSESSMENT", lines=tuple(assessment)),
            ReportBlock("REVIEW", lines=tuple(review)),
            detail_block,
        ),
    )


def _host_section(result: AreaResult, details: bool) -> ReportSection:
    """The five identity rows the legacy view showed (environment is not shown)."""
    facts = {fact.key: fact for fact in result.facts}
    distribution = facts["distribution"].value
    if facts["distribution_version"].raw:
        distribution += f" ({facts['distribution_version'].value})"
    return ReportSection(
        title=result.title,
        facts=(
            ("Hostname", facts["hostname"].value),
            ("Distribution", distribution),
            ("Kernel", facts["kernel_release"].value),
            ("Architecture", facts["architecture"].value),
            ("Uptime", facts["uptime"].value),
        ),
    )


def _system_info(result: AreaResult) -> SystemInfo | None:
    """Rebuild the typed host identity the legacy renderers read."""
    if result.area_id != "host" or result.status in {AreaStatus.NOT_ASSESSED, AreaStatus.ERROR}:
        return None
    raw = {fact.key: fact.raw for fact in result.facts}
    return SystemInfo(
        hostname=raw.get("hostname"),
        distribution=raw.get("distribution"),
        distribution_version=raw.get("distribution_version"),
        kernel_release=raw.get("kernel_release"),
        architecture=raw.get("architecture"),
        uptime_seconds=raw.get("uptime"),
    )


_LEGACY_SECTIONS: dict[str, Callable[[AreaResult, bool], ReportSection]] = {
    "ssh_host_keys": _ssh_host_keys_section,
    "host": _host_section,
    "hardening": _hardening_section,
    "users": _users_section,
}


def area_result_to_section(result: AreaResult, *, details: bool = False) -> ReportSection:
    """Convert one area into a legacy section."""
    if result.status in {AreaStatus.NOT_ASSESSED, AreaStatus.ERROR}:
        return ReportSection(
            result.title,
            status=result.status.value,
            message="; ".join(gap.message for gap in result.gaps),
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
        host=_system_info(result),
        privilege=privilege,
    )
