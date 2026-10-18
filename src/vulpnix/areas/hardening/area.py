"""Kernel hardening parameters, expressed through the Area contract.

Collection and rules are unchanged (``collectors.hardening``,
``rules.hardening``). A fixed allow-list of sysctl values is read; nothing is
ever written.

Every parameter becomes a fact carrying the rule's own judgment, so a value and
its finding cannot disagree. Where each outcome goes:

* FAIL and REVIEW: a fact plus a finding;
* PASS: a fact;
* a required parameter that could not be read: a fact marked NOT_ASSESSED plus
  a *gap* (coverage limit, not a security observation);
* an optional parameter that this kernel does not expose: only the NOT_ASSESSED
  fact, because its absence is expected and does not reduce coverage.
"""

from __future__ import annotations

from collections.abc import Callable

from vulpnix.collectors.hardening import collect_sysctl_observations
from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Fact, FindingStatus, Gap
from vulpnix.models import HardeningCheck, SysctlObservation
from vulpnix.rules.hardening import assess_kernel_hardening

NOTE = (
    "Read-only sysctl checks. Role-dependent settings are marked REVIEW, "
    "not automatically treated as vulnerabilities."
)

_ASSESSED = {FindingStatus.PASS, FindingStatus.FAIL, FindingStatus.REVIEW}
_NOT_ASSESSED = {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR}


def _fact(check: HardeningCheck) -> Fact:
    detail = f"expected {check.expected}"
    if check.reason:
        detail += f"; {check.reason}"
    return Fact(
        key=check.key,
        label=check.title,
        value=check.observed if check.observed is not None else "unavailable",
        status=check.status,
        raw=int(check.observed) if check.status in _ASSESSED else None,
        detail=detail,
    )


def _reduces_coverage(check: HardeningCheck) -> bool:
    """A missing optional parameter is expected; unreadable data never is."""
    if check.status is FindingStatus.ERROR:
        return True
    return check.status is FindingStatus.NOT_ASSESSED and not check.optional


class KernelHardeningArea:
    """Selected kernel and network hardening parameters."""

    id = "hardening"
    title = "KERNEL HARDENING"
    description = "Read-only kernel hardening checks"

    def __init__(
        self,
        collector: Callable[[], tuple[SysctlObservation, ...]] | None = None,
    ) -> None:
        # ``None`` resolves the collector at run time so tests can patch it.
        self._collector = collector

    def run(self, ctx: ExecutionContext) -> AreaResult:
        collector = self._collector or collect_sysctl_observations
        assessment = assess_kernel_hardening(collector())

        facts = tuple(_fact(check) for check in assessment.checks)
        gaps = tuple(
            Gap(
                f"sysctl_not_assessed:{check.key}",
                f"{check.key}: {check.reason or 'value unavailable'}",
            )
            for check in assessment.checks
            if _reduces_coverage(check)
        )
        findings = tuple(
            finding for finding in assessment.findings
            if finding.status in {FindingStatus.FAIL, FindingStatus.REVIEW}
        )

        if gaps and not any(fact.status in _ASSESSED for fact in facts):
            status = AreaStatus.NOT_ASSESSED
        elif gaps:
            status = AreaStatus.PARTIAL
        else:
            status = AreaStatus.COMPLETE
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=status,
            findings=findings,
            facts=facts,
            gaps=gaps,
            notes=(NOTE,),
        )
