"""Ownership and permissions of systemd unit files, as an Area.

Collection and rules are unchanged (``collectors.systemd_security``,
``rules.systemd_security``). Only file metadata is read, never contents, and
symlinks are not followed.

The service list comes from the shared observation, so no second systemd query
is made for it. If the services could not be observed, this area says so and is
NOT_ASSESSED: its input is missing, which is a coverage limit, not a verdict.

Where each outcome goes:

* FAIL and REVIEW: a record plus a finding;
* PASS: a record;
* a file that could not be inspected: a record marked NOT_ASSESSED plus a gap;
* every note the collector reports (unit budget, templates, masked units): a gap.
"""

from __future__ import annotations

from collections.abc import Callable

from vulpnix.areas.services.area import observe_services, services_error_message
from vulpnix.collectors.systemd_security import collect_service_unit_file_metadata
from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, FindingStatus, Gap, Record
from vulpnix.core.errors import EXPECTED_FAILURES
from vulpnix.models import Service, UnitFileObservation
from vulpnix.rules.systemd_security import assess_systemd_unit_metadata

NOTE = (
    "File contents are not read. Writable or non-root-owned service definitions "
    "can affect privileged service execution."
)
UNIT_FILES_UNAVAILABLE = "unit-files-unavailable"

_NOT_INSPECTED = {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR}
_ASSESSED = {FindingStatus.PASS, FindingStatus.FAIL, FindingStatus.REVIEW}

Collector = Callable[
    [tuple[Service, ...]],
    tuple[tuple[UnitFileObservation, ...], tuple[str, ...]],
]


class UnitFilesArea:
    """Ownership and write permissions of service unit fragments and drop-ins."""

    id = "unit_files"
    title = "SYSTEMD UNIT FILES"
    description = "systemd unit-file ownership and permissions"

    def __init__(
        self,
        collector: Collector | None = None,
        services_collector: Callable[[], tuple[Service, ...]] | None = None,
    ) -> None:
        self._collector = collector
        self._services_collector = services_collector

    def _unavailable(self, error: Exception) -> AreaResult:
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=AreaStatus.NOT_ASSESSED,
            gaps=(
                Gap(
                    UNIT_FILES_UNAVAILABLE,
                    f"Unit-file metadata is unavailable: {services_error_message(error)}",
                ),
            ),
        )

    def run(self, ctx: ExecutionContext) -> AreaResult:
        try:
            services = observe_services(ctx, self._services_collector)
            collector = self._collector or collect_service_unit_file_metadata
            observations, collection_review = collector(services)
        except EXPECTED_FAILURES as error:
            return self._unavailable(error)

        assessment = assess_systemd_unit_metadata(observations, collection_review)
        records: list[Record] = []
        gaps: list[Gap] = []
        # The rules return exactly one check per observation, in order.
        for observation, check in zip(observations, assessment.checks, strict=True):
            records.append(
                Record(
                    kind="unit_file",
                    key=observation.path,
                    label=observation.path,
                    fields=(
                        ("unit", observation.unit),
                        ("path", observation.path),
                        ("owner_uid", observation.owner_uid),
                        ("mode", observation.mode),
                        ("is_regular", observation.is_regular),
                        ("is_symlink", observation.is_symlink),
                        ("error", observation.error),
                        ("evidence", check.evidence),
                    ),
                    status=check.status,
                )
            )
            if check.status in _NOT_INSPECTED:
                gaps.append(
                    Gap(
                        f"unit_file_not_inspected:{observation.path}",
                        check.evidence,
                        subject=observation.unit,
                        cause=check.reason,
                    )
                )
        gaps.extend(
            Gap(f"collection_review:{index}", note)
            for index, note in enumerate(collection_review)
        )
        if not records and not gaps:
            # Fail closed: a check that examined nothing never reports COMPLETE.
            gaps.append(Gap("nothing-inspected", "No unit-file metadata was available to inspect."))

        findings = tuple(
            finding for finding in assessment.findings
            if finding.status not in _NOT_INSPECTED
        )
        assessed = any(record.status in _ASSESSED for record in records)
        if gaps and not assessed:
            status = AreaStatus.NOT_ASSESSED
        elif gaps:
            status = AreaStatus.PARTIAL
        else:
            status = AreaStatus.COMPLETE
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=status,
            findings=() if status is AreaStatus.NOT_ASSESSED else findings,
            records=tuple(records),
            gaps=tuple(gaps),
            notes=(NOTE,),
        )
