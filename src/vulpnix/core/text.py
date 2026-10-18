"""Pure text helpers for values collected from the observed system.

Values read from the host (hostnames, release strings, error messages) may
contain control characters. They are made printable here, once, so no area or
renderer has to remember to do it.
"""

from __future__ import annotations

REPLACEMENT = "\N{REPLACEMENT CHARACTER}"
UNAVAILABLE = "Unavailable"


def printable(text: str) -> str:
    """Replace non-printable characters instead of passing them through."""
    return "".join(ch if ch.isprintable() else REPLACEMENT for ch in text)


def display_text(value: str | None, *, limit: int = 80) -> str:
    """One safe, bounded line for a locally collected value.

    Values longer than ``limit`` keep their first ``limit - 3`` characters and
    end with an ellipsis, exactly as the terminal always showed them.
    """
    if not value:
        return UNAVAILABLE
    safe = printable(value)
    if len(safe) > limit:
        return safe[: limit - 3] + "…"
    return safe


def format_uptime(seconds: float | None) -> str:
    """Whole minutes as ``1d 2h 3m``; sub-minute uptimes read ``0m``."""
    if seconds is None:
        return UNAVAILABLE
    minutes = int(seconds // 60)
    days, remaining_minutes = divmod(minutes, 24 * 60)
    hours, remaining_minutes = divmod(remaining_minutes, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if remaining_minutes or not parts:
        parts.append(f"{remaining_minutes}m")
    return " ".join(parts)
