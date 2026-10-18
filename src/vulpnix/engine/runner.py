"""Run areas with failure isolation."""

from __future__ import annotations

import subprocess

from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Gap
from vulpnix.core.text import printable
from vulpnix.engine.area import Area

# Failures caused by the observed system (missing files, unreadable output,
# failing commands). Anything else is a Vulpnix bug and must surface.
EXPECTED_FAILURES = (OSError, subprocess.SubprocessError, UnicodeError, ValueError)


def run_area(area: Area, ctx: ExecutionContext) -> AreaResult:
    """Run one area; an expected failure becomes an ERROR result, not a crash.

    An ERROR result is never a security verdict: it only records that the
    area could not be assessed.
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
    return result
