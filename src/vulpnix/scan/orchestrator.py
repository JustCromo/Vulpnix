from __future__ import annotations

from collections.abc import Callable
import subprocess

from vulpnix.cli.report import ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.collectors.network import collect_network_snapshot
from vulpnix.context import current_execution_context
from vulpnix.models import NetworkSnapshot
from vulpnix.scan.progress import ScanProgress, ScanStage
from vulpnix.scan.result import ScanResult

NetworkSectionBuilder = Callable[[NetworkSnapshot], ReportSection]


class ScanOrchestrator:
    """Run scans as a shared lifecycle: progress -> collection -> assessment -> result."""

    def __init__(self, *, progress_callback: Callable[[ScanProgress], None] | None = None) -> None:
        self._progress_callback = progress_callback
        # One source of truth: the same context every Area receives.
        self._privilege = current_execution_context().privilege

    def _emit(self, stage: ScanStage, message: str, *, completed: int = 0, total: int | None = None) -> None:
        if self._progress_callback is not None:
            self._progress_callback(ScanProgress(stage, message, completed, total))

    def _result(self, **kwargs: object) -> ScanResult:
        return ScanResult(privilege=self._privilege, **kwargs)

    def run_network(
        self,
        *,
        section_builder: NetworkSectionBuilder,
        collector: Callable[[], NetworkSnapshot] = collect_network_snapshot,
    ) -> ScanResult:
        """Collect the local socket inventory and record limits on process attribution."""
        self._emit(ScanStage.STARTING, "Starting network exposure assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Collecting listening and bound sockets")
            snapshot = collector()
            self._emit(ScanStage.ASSESSING, "Classifying socket bind scopes")
            section = section_builder(snapshot)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
            self._emit(ScanStage.ERROR, f"Network exposure assessment failed: {error}")
            raise
        incomplete = bool(snapshot.review) or (bool(snapshot.endpoints) and not snapshot.process_attribution_complete)
        self._emit(ScanStage.COMPLETED, "Network exposure assessment completed")
        return self._result(
            sections=(section,),
            scope=("listening sockets", "local bind scope"),
            coverage=AssessmentCoverage.PARTIAL if incomplete else AssessmentCoverage.COMPLETE,
            review_items=max(len(snapshot.review), 1 if bool(snapshot.endpoints) and not snapshot.process_attribution_complete else 0),
        )
