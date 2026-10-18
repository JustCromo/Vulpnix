"""Structured, presentation-free results produced by assessment areas.

Nothing in this module knows about terminals, colors, HTML or line wrapping.
Areas decide what they observed and how it should be judged; renderers decide
only how to show it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from vulpnix.findings import Finding, FindingStatus


class AreaStatus(Enum):
    """How much of an area could actually be collected and evaluated."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


@dataclass(frozen=True, slots=True)
class Fact:
    """One observed value, with an optional judgment decided by the area.

    ``key`` is stable and machine-readable; ``label`` is for people.
    ``value`` is display text. ``raw`` is the observed value in its natural
    type (for example uptime in seconds) when the text would lose information;
    it is ``None`` when the value was not available.
    ``status`` is set only when the area has an evidence-backed judgment for
    this value. Renderers must never infer a status from ``label`` or ``value``.
    """

    key: str
    label: str
    value: str
    status: FindingStatus | None = None
    raw: str | int | float | bool | None = None


@dataclass(frozen=True, slots=True)
class Gap:
    """Something the area could not verify, and why.

    Gaps make an area PARTIAL. They are not vulnerabilities and are never
    converted into findings or risk scores.
    """

    key: str
    message: str


@dataclass(frozen=True, slots=True)
class AreaResult:
    """Everything one area observed, judged and could not verify.

    The result is always complete: ``--details`` is a rendering choice, not a
    reason to collect or build different data.
    """

    area_id: str
    title: str
    status: AreaStatus
    findings: tuple[Finding, ...] = ()
    facts: tuple[Fact, ...] = ()
    gaps: tuple[Gap, ...] = ()
    notes: tuple[str, ...] = field(default=())
    """Scope limits that hold by design (e.g. "global options only").

    Notes do not reduce coverage; gaps do.
    """

    def __post_init__(self) -> None:
        if not self.area_id.strip():
            raise ValueError("Area id must not be empty.")
        if self.status is AreaStatus.COMPLETE and self.gaps:
            raise ValueError("An area with gaps cannot be COMPLETE.")
        if self.status is AreaStatus.PARTIAL and not self.gaps:
            raise ValueError("A PARTIAL area must say what was not verified.")
        if self.status in {AreaStatus.NOT_ASSESSED, AreaStatus.ERROR}:
            if not self.gaps:
                raise ValueError(f"A {self.status.value} area must explain why.")
            if self.findings:
                raise ValueError(f"A {self.status.value} area cannot report findings.")
