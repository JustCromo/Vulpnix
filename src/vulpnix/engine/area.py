"""The single contract every assessment area implements."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult


@runtime_checkable
class Area(Protocol):
    """One independently collected and assessed part of the host.

    An area collects read-only evidence, judges it with its own rules and
    returns an ``AreaResult``. It never prints, colors or formats output.
    """

    id: str
    """Stable identifier used by the CLI, e.g. ``"ssh"``."""

    title: str
    """Human-readable section title, e.g. ``"SSH"``."""

    description: str
    """One-line description used for help and completions."""

    def run(self, ctx: ExecutionContext) -> AreaResult:
        """Collect, assess and summarize this area."""
        ...
