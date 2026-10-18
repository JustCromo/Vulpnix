"""Execution context passed to every assessment area.

The context is collected once per scan, read-only, and never elevates
privileges. Detection is conservative: when the evidence is unclear the
environment is reported as UNKNOWN instead of guessed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import shutil

from vulpnix.scan.privilege import PrivilegeContext, current_privilege_context


class Environment(Enum):
    """Kind of system the scan observes."""

    NATIVE = "NATIVE"
    WSL = "WSL"
    CONTAINER = "CONTAINER"
    UNKNOWN = "UNKNOWN"


_CONTAINER_MARKERS = ("/.dockerenv", "/run/.containerenv")


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def detect_environment(
    *,
    root: Path = Path("/"),
    environ: Mapping[str, str] | None = None,
) -> Environment:
    """Classify the observed system from read-only evidence.

    ``root`` and ``environ`` exist so tests can supply fixtures.
    """
    env = os.environ if environ is None else environ

    osrelease = _read_text(root / "proc/sys/kernel/osrelease")
    if env.get("WSL_DISTRO_NAME") or (
        osrelease is not None and "microsoft" in osrelease.lower()
    ):
        return Environment.WSL

    if any((root / marker.lstrip("/")).exists() for marker in _CONTAINER_MARKERS):
        return Environment.CONTAINER
    if env.get("container"):
        return Environment.CONTAINER

    if osrelease is None:
        return Environment.UNKNOWN
    return Environment.NATIVE


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Privileges, environment and command lookup shared by all areas."""

    privilege: PrivilegeContext
    environment: Environment
    which: Callable[[str], str | None] = shutil.which

    @property
    def privileged(self) -> bool:
        return self.privilege.privileged


def current_execution_context() -> ExecutionContext:
    """Collect the context for the running Vulpnix process."""
    return ExecutionContext(
        privilege=current_privilege_context(),
        environment=detect_environment(),
    )
