"""Run areas with failure isolation and output sanitization."""

from __future__ import annotations

from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Gap
from vulpnix.core.errors import EXPECTED_FAILURES
from vulpnix.core.sanitize import sanitize_result
from vulpnix.core.text import printable
from vulpnix.engine.area import Area

__all__ = ["EXPECTED_FAILURES", "run_area"]


def run_area(area: Area, ctx: ExecutionContext) -> AreaResult:
    """Run one area; an expected failure becomes an ERROR result, not a crash.

    An ERROR result is never a security verdict: it only records that the
    area could not be assessed. Whatever the area returns is sanitized here,
    so observed data cannot reach a renderer with control characters in it.
    """
    try:
        result = area.run(ctx)
    except EXPECTED_FAILURES as error:
        detail = printable(str(error)) or type(error).__name__
        return AreaResult(
            area_id=area.id,
            title=area.title,
            status=AreaStatus.ERROR,
            gaps=(Gap("area-error", f"{area.title} could not be assessed: {detail}"),),
        )
    if result.area_id != area.id:
        raise ValueError(
            f"Area {area.id!r} returned a result for {result.area_id!r}."
        )
    return sanitize_result(result)
