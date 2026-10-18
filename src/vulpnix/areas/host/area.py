"""Host identity facts, expressed through the Area contract.

The collector is unchanged. This area reports what the host says about
itself (name, distribution, kernel, architecture, uptime) plus the kind of
environment Vulpnix is running in. These facts describe the system; they carry
no security judgment and never produce findings.
"""

from __future__ import annotations

from collections.abc import Callable

from vulpnix.collectors.host import collect_system_info
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Fact, Gap
from vulpnix.core.text import display_text, format_uptime
from vulpnix.models import SystemInfo

UNSUPPORTED_PLATFORM = "unsupported-platform"
HOST_FACTS_UNAVAILABLE = "host-facts-unavailable"

_ENVIRONMENT_LABELS = {
    Environment.NATIVE: "Native Linux",
    Environment.WSL: "WSL",
    Environment.CONTAINER: "Container",
    Environment.UNKNOWN: "Unknown",
}

_ENVIRONMENT_NOTES = {
    Environment.WSL: (
        "Running under WSL: the kernel and Windows host protections are managed "
        "outside this Linux system and are not assessed."
    ),
    Environment.CONTAINER: (
        "Running inside a container: kernel parameters, network and firewall state "
        "may belong to the container host rather than to this container."
    ),
}


class HostArea:
    """Name, distribution, kernel, architecture, uptime and environment."""

    id = "host"
    title = "SYSTEM"
    description = "Host facts"

    def __init__(self, collector: Callable[[], SystemInfo] | None = None) -> None:
        # ``None`` resolves the collector at run time so tests can patch it.
        self._collector = collector

    def run(self, ctx: ExecutionContext) -> AreaResult:
        collector = self._collector or collect_system_info
        try:
            info = collector()
        except NotImplementedError:
            return self._not_assessed(
                Gap(UNSUPPORTED_PLATFORM, "Host facts are supported on Linux only.")
            )
        except (OSError, UnicodeError, ValueError) as error:
            return self._not_assessed(
                Gap(
                    HOST_FACTS_UNAVAILABLE,
                    "Host information could not be collected reliably: "
                    f"{display_text(str(error))}",
                )
            )

        facts = (
            Fact("hostname", "Hostname", display_text(info.hostname), raw=info.hostname),
            Fact(
                "distribution",
                "Distribution",
                display_text(info.distribution),
                raw=info.distribution,
            ),
            Fact(
                "distribution_version",
                "Distribution version",
                display_text(info.distribution_version),
                raw=info.distribution_version,
            ),
            Fact("kernel_release", "Kernel", display_text(info.kernel_release), raw=info.kernel_release),
            Fact("architecture", "Architecture", display_text(info.architecture), raw=info.architecture),
            Fact("uptime", "Uptime", format_uptime(info.uptime_seconds), raw=info.uptime_seconds),
            Fact(
                "environment",
                "Environment",
                _ENVIRONMENT_LABELS[ctx.environment],
                raw=ctx.environment.value,
            ),
        )
        note = _ENVIRONMENT_NOTES.get(ctx.environment)
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=AreaStatus.COMPLETE,
            facts=facts,
            notes=(note,) if note else (),
        )

    def _not_assessed(self, gap: Gap) -> AreaResult:
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=AreaStatus.NOT_ASSESSED,
            gaps=(gap,),
        )
