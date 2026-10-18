"""systemd services, expressed through the Area contract.

Collection and parsing are unchanged (``collectors.systemd``,
``parsers.systemd``). The service list is an *observation* shared through the
execution context: the unit-file area reads the same list instead of querying
systemd a second time, so both sections describe the same snapshot.

Each service is a record. A service whose state or startup enablement is
genuinely unknown is a gap (one per service), so the area says exactly what it
could not establish.
"""

from __future__ import annotations

from collections.abc import Callable
import subprocess

from vulpnix.collectors.systemd import collect_services
from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Gap, Fact, Record
from vulpnix.core.errors import EXPECTED_FAILURES
from vulpnix.core.text import printable
from vulpnix.models import Service
from vulpnix.parsers.systemd import UNIT_FILE_NON_BOOLEAN_STATES

SERVICES_KEY = "systemd.services"
_SERVICES_SOURCE = "systemctl --system list-units and list-unit-files (services)"
SERVICES_UNAVAILABLE = "services-unavailable"


def observe_services(
    ctx: ExecutionContext,
    collector: Callable[[], tuple[Service, ...]] | None = None,
) -> tuple[Service, ...]:
    """The service list for this scan: collected once, shared by every area."""
    # The collector is resolved here, at call time, so tests can patch it.
    return ctx.observations.get(
        SERVICES_KEY, collector or collect_services, source=_SERVICES_SOURCE
    )


def services_error_message(error: Exception) -> str:
    """Explain, in one sentence, why systemd could not be queried."""
    if isinstance(error, FileNotFoundError):
        return "systemctl is not installed."
    if isinstance(error, subprocess.TimeoutExpired):
        return "systemctl did not respond in time."
    if isinstance(error, subprocess.CalledProcessError):
        return "systemd could not be queried; access may be restricted."
    if isinstance(error, (UnicodeError, ValueError)):
        return "systemd returned unreadable service data."
    return "systemd service data is unavailable."


def _unknowns(service: Service) -> list[str]:
    unknown = []
    if service.state is not None and service.state.strip().lower() in {"unknown", ""}:
        unknown.append("state")
    unit_state = (service.unit_file_state or "").strip().lower()
    if service.enabled is None and unit_state not in UNIT_FILE_NON_BOOLEAN_STATES:
        unknown.append("startup enablement")
    return unknown


class ServicesArea:
    """Service state and startup enablement."""

    id = "services"
    title = "SERVICES"
    description = "Services and startup state"

    def __init__(self, collector: Callable[[], tuple[Service, ...]] | None = None) -> None:
        self._collector = collector

    def run(self, ctx: ExecutionContext) -> AreaResult:
        try:
            services = observe_services(ctx, self._collector)
        except EXPECTED_FAILURES as error:
            return AreaResult(
                area_id=self.id,
                title=self.title,
                status=AreaStatus.NOT_ASSESSED,
                gaps=(Gap(SERVICES_UNAVAILABLE, services_error_message(error)),),
            )

        records = tuple(
            Record(
                kind="service",
                key=service.name,
                label=printable(service.name),
                fields=(
                    ("state", service.state),
                    ("enabled", service.enabled),
                    ("unit_file_state", service.unit_file_state),
                ),
            )
            for service in services
        )
        gaps = []
        for service in services:
            unknown = _unknowns(service)
            if unknown:
                cause = " and ".join(unknown) + " unknown"
                gaps.append(
                    Gap(
                        f"service_unknown:{service.name}",
                        f"{service.name}: {cause}",
                        subject=service.name,
                        cause=cause,
                    )
                )
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=AreaStatus.PARTIAL if gaps else AreaStatus.COMPLETE,
            facts=(Fact("units", "Units", str(len(services)), raw=len(services)),),
            records=records,
            gaps=tuple(gaps),
        )
