"""Read-only collection of basic Linux host facts."""

import math
import platform
from pathlib import Path

from vulpnix.models import SystemInfo


def _read_os_release() -> dict[str, str]:
    """Read distribution metadata without evaluating it as shell code."""
    try:
        return platform.freedesktop_os_release()
    except OSError:
        return {}


def _read_uptime_seconds() -> float | None:
    """Read and validate the first value in Linux's /proc/uptime."""
    try:
        raw_uptime = Path("/proc/uptime").read_text(encoding="ascii").split()[0]
        uptime_seconds = float(raw_uptime)
    except (OSError, UnicodeError, ValueError, IndexError):
        return None

    if not math.isfinite(uptime_seconds) or uptime_seconds < 0:
        return None
    return uptime_seconds


def collect_system_info() -> SystemInfo:
    """Collect basic host facts without running external commands."""
    if platform.system() != "Linux":
        raise NotImplementedError("System information collection is supported only on Linux.")

    os_release = _read_os_release()

    return SystemInfo(
        hostname=platform.node() or None,
        distribution=(
            os_release.get("PRETTY_NAME")
            or os_release.get("NAME")
            or os_release.get("ID")
            or None
        ),
        distribution_version=os_release.get("VERSION_ID") or None,
        kernel_release=platform.release() or None,
        architecture=platform.machine() or None,
        uptime_seconds=_read_uptime_seconds(),
    )
