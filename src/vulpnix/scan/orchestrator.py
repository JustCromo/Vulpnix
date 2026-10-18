from __future__ import annotations

from collections.abc import Callable
import subprocess

from vulpnix.cli.report import ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.collectors import (
    collect_setid_files,
    collect_sensitive_file_metadata,
)
from vulpnix.collectors.network import collect_network_snapshot
from vulpnix.findings import Finding
from vulpnix.models import (
    FileMetadataResult,
    FilesystemCoverage,
    NetworkSnapshot,
)
from vulpnix.rules.filesystem import (
    FilesystemAssessment,
    SetIdAssessment,
    assess_sensitive_files,
    assess_setid_files,
)
from vulpnix.context import current_execution_context
from vulpnix.scan.progress import ScanProgress, ScanStage
from vulpnix.scan.result import ScanResult

FilesystemSectionBuilder = Callable[
    [tuple[FileMetadataResult, ...], FilesystemAssessment, FilesystemCoverage, SetIdAssessment],
    ReportSection,
]
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

    def run_filesystem(self, *, section_builder: FilesystemSectionBuilder, sensitive_file_collector: Callable[[], tuple[FileMetadataResult, ...]] = collect_sensitive_file_metadata, sensitive_file_assessor: Callable[[tuple[FileMetadataResult, ...]], FilesystemAssessment] = assess_sensitive_files, setid_collector: Callable[[], FilesystemCoverage] = collect_setid_files, setid_assessor: Callable[[FilesystemCoverage], SetIdAssessment] = assess_setid_files) -> ScanResult:
        self._emit(ScanStage.STARTING, "Starting filesystem assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Collecting sensitive file metadata")
            results = sensitive_file_collector()
            self._emit(ScanStage.ASSESSING, "Assessing sensitive file metadata")
            assessment = sensitive_file_assessor(results)
            self._emit(ScanStage.COLLECTING, "Collecting set-ID files")
            coverage = setid_collector()
            self._emit(ScanStage.ASSESSING, "Assessing set-ID files")
            setid_assessment = setid_assessor(coverage)
            self._emit(ScanStage.ASSESSING, "Building filesystem report")
            section = section_builder(results, assessment, coverage, setid_assessment)
        except (OSError, UnicodeError, ValueError) as error:
            self._emit(ScanStage.ERROR, f"Filesystem assessment failed: {error}")
            raise
        review_items = len(assessment.review) + len(setid_assessment.review)
        if coverage.status.name in {"PARTIAL", "NOT_ASSESSED", "ERROR"}:
            review_items += 1
        self._emit(ScanStage.COMPLETED, "Filesystem assessment completed")
        return self._result(
            sections=(section,),
            findings=(*assessment.findings, *setid_assessment.findings),
            scope=("filesystem metadata", "set-ID files"),
            coverage=AssessmentCoverage.PARTIAL if review_items else AssessmentCoverage.COMPLETE,
            review_items=review_items,
        )

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

    def run_full_scan(
        self,
        *,
        filesystem_section_builder: FilesystemSectionBuilder,
        services_result: Callable[[], ScanResult],
        users_result: Callable[[], ScanResult],
        sensitive_file_collector: Callable[[], tuple[FileMetadataResult, ...]] = collect_sensitive_file_metadata,
        sensitive_file_assessor: Callable[[tuple[FileMetadataResult, ...]], FilesystemAssessment] = assess_sensitive_files,
        setid_collector: Callable[[], FilesystemCoverage] = collect_setid_files,
        setid_assessor: Callable[[FilesystemCoverage], SetIdAssessment] = assess_setid_files,
    ) -> ScanResult:
        self._emit(ScanStage.STARTING, "Starting full Linux assessment", total=5)
        sections: list[ReportSection] = []
        findings: list[Finding] = []
        review_items = 0

        # Services are produced by the Services area; this seam disappears once
        # the remaining areas are migrated.
        self._emit(ScanStage.COLLECTING, "Collecting services", completed=1, total=5)
        services = services_result()
        sections.extend(services.sections)
        findings.extend(services.findings)
        review_items += services.review_items

        # Users are produced by the Users area; this seam disappears once the
        # remaining areas are migrated.
        self._emit(ScanStage.COLLECTING, "Collecting local accounts and privileges", completed=2, total=5)
        users = users_result()
        sections.extend(users.sections)
        findings.extend(users.findings)
        review_items += users.review_items

        try:
            self._emit(ScanStage.COLLECTING, "Collecting sensitive file metadata", completed=3, total=5)
            file_results = sensitive_file_collector()
            self._emit(ScanStage.ASSESSING, "Assessing sensitive file metadata", completed=4, total=5)
            fs_assessment = sensitive_file_assessor(file_results)
            self._emit(ScanStage.COLLECTING, "Collecting set-ID files", completed=5, total=5)
            setid_coverage = setid_collector()
            setid_assessment = setid_assessor(setid_coverage)
            sections.append(filesystem_section_builder(file_results, fs_assessment, setid_coverage, setid_assessment))
            findings.extend((*fs_assessment.findings, *setid_assessment.findings))
            review_items += len(fs_assessment.review) + len(setid_assessment.review)
            if setid_coverage.status.name in {"PARTIAL", "NOT_ASSESSED", "ERROR"}:
                review_items += 1
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
            sections.append(ReportSection("FILESYSTEM", status="NOT_ASSESSED", message="Filesystem checks could not be fully assessed with the current privileges."))
            review_items += 1

        coverage = AssessmentCoverage.PARTIAL if review_items else AssessmentCoverage.COMPLETE
        self._emit(ScanStage.COMPLETED, "Full Linux assessment completed", completed=5, total=5)
        return self._result(
            sections=tuple(sections),
            findings=tuple(findings),
            scope=("users", "services", "filesystem metadata", "set-ID files"),
            coverage=coverage,
            review_items=review_items,
        )
