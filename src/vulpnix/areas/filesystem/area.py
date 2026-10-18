"""Sensitive system files and set-ID executables, expressed through the Area contract.

Collection and rules are unchanged (``collectors.filesystem``,
``collectors.setid``, ``rules.filesystem``). The set-ID collector is the
security-critical part: it walks the tree with no-follow, descriptor-relative
operations, verifies that files do not change under it, and stays within entry
and time budgets. None of that is touched here.

Where each outcome goes:

* a verified insecure condition: a FAIL finding (the rules decide);
* each fixed sensitive file and each discovered set-ID file: a record;
* everything the rules or the collector say could not be verified or was not
  assessed (unmapped owners, group-readable policy, unexpected file types,
  missing ELF or mount evidence, exhausted budgets): a gap, one per statement.

The two collectors are independent. If one fails the other still contributes, and
the failure is a gap that says so.
"""

from __future__ import annotations

from collections.abc import Callable

from vulpnix.collectors.filesystem import collect_sensitive_file_metadata
from vulpnix.collectors.setid import collect_setid_files
from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Fact, FindingStatus, Gap, Record
from vulpnix.core.errors import EXPECTED_FAILURES
from vulpnix.core.text import display_text
from vulpnix.models import (
    CoverageStatus,
    FileMetadataResult,
    FileMetadataStatus,
    FilesystemCoverage,
)
from vulpnix.rules.filesystem import assess_setid_files, assess_sensitive_files

SENSITIVE_UNAVAILABLE = "sensitive-files-unavailable"
SETID_UNAVAILABLE = "setid-unavailable"
SETID_COVERAGE = "setid_coverage"

_UNRESOLVED_COVERAGE = {CoverageStatus.PARTIAL, CoverageStatus.NOT_ASSESSED, CoverageStatus.ERROR}
_COLLECTED = {FileMetadataStatus.COLLECTED, FileMetadataStatus.PARTIAL}


def _finding_path(evidence: str) -> str:
    """The path a filesystem finding is about (its evidence starts with it)."""
    return evidence.split(";", 1)[0].removeprefix("Path: ")


class FilesystemArea:
    """Fixed sensitive files in /etc and bounded set-ID discovery."""

    id = "filesystem"
    title = "FILESYSTEM"
    description = "Sensitive file metadata and set-ID checks"

    def __init__(
        self,
        sensitive_collector: Callable[[], tuple[FileMetadataResult, ...]] | None = None,
        setid_collector: Callable[[], FilesystemCoverage] | None = None,
    ) -> None:
        # ``None`` resolves collectors at run time so tests can patch them.
        self._sensitive_collector = sensitive_collector
        self._setid_collector = setid_collector

    def run(self, ctx: ExecutionContext) -> AreaResult:
        sensitive_collector = self._sensitive_collector or collect_sensitive_file_metadata
        setid_collector = self._setid_collector or collect_setid_files
        records: list[Record] = []
        facts: list[Fact] = []
        gaps: list[Gap] = []
        findings = []
        assessed = False

        try:
            results = sensitive_collector()
        except EXPECTED_FAILURES as error:
            gaps.append(
                Gap(
                    SENSITIVE_UNAVAILABLE,
                    f"Filesystem checks could not be fully assessed: {display_text(str(error))}",
                )
            )
        else:
            assessment = assess_sensitive_files(results)
            findings.extend(assessment.findings)
            assessed = assessed or bool(assessment.checked)
            checked_paths = {metadata.path for metadata in assessment.checked}
            finding_paths = {_finding_path(finding.evidence) for finding in assessment.findings}
            review_paths = {item.path for item in assessment.review}
            for result in results:
                metadata = result.metadata
                if result.path in finding_paths:
                    status = FindingStatus.FAIL
                elif result.status is FileMetadataStatus.NOT_ASSESSED or metadata is None:
                    status = FindingStatus.NOT_ASSESSED
                elif result.path in review_paths:
                    status = FindingStatus.REVIEW
                elif result.path in checked_paths:
                    status = FindingStatus.PASS
                else:
                    status = None
                records.append(
                    Record(
                        kind="sensitive_file",
                        key=result.path,
                        label=result.path,
                        fields=(
                            ("type", metadata.type if metadata else None),
                            ("uid", metadata.uid if metadata else None),
                            ("gid", metadata.gid if metadata else None),
                            ("mode", metadata.mode if metadata else None),
                            ("size", metadata.size if metadata else None),
                            ("collection_status", result.status.value),
                            ("reason", result.reason),
                            ("assessed", result.path in checked_paths),
                        ),
                        status=status,
                    )
                )
            gaps.extend(
                Gap(f"fs_review:{index}", f"{item.path}: {item.reason}", subject=item.path, cause=item.reason)
                for index, item in enumerate(assessment.review)
            )

        try:
            coverage = setid_collector()
        except EXPECTED_FAILURES as error:
            gaps.append(
                Gap(
                    SETID_UNAVAILABLE,
                    f"Filesystem checks could not be fully assessed: {display_text(str(error))}",
                )
            )
        else:
            setid = assess_setid_files(coverage)
            findings.extend(setid.findings)
            assessed = assessed or coverage.status in {CoverageStatus.COLLECTED, CoverageStatus.PARTIAL}
            setid_finding_paths = {_finding_path(finding.evidence) for finding in setid.findings}
            for item in coverage.files:
                metadata = item.metadata
                records.append(
                    Record(
                        kind="setid_file",
                        key=metadata.path,
                        label=metadata.path,
                        fields=(
                            ("type", metadata.type),
                            ("uid", metadata.uid),
                            ("gid", metadata.gid),
                            ("mode", metadata.mode),
                            ("size", metadata.size),
                            ("is_elf", item.is_elf),
                            ("mount_options", item.mount_options),
                            ("reason", item.reason),
                        ),
                        status=FindingStatus.FAIL if metadata.path in setid_finding_paths else None,
                    )
                )
            gaps.extend(Gap(f"setid_review:{index}", text) for index, text in enumerate(setid.review))
            if coverage.status in _UNRESOLVED_COVERAGE:
                gaps.append(
                    Gap(SETID_COVERAGE, f"Set-ID discovery coverage is {coverage.status.value}.")
                )
            facts.extend((
                Fact("setid_discovery", "Set-ID discovery", coverage.status.value, raw=coverage.status.value),
                Fact("entries_examined", "Entries examined", str(coverage.entries_examined), raw=coverage.entries_examined),
                Fact("setid_roots", "Set-ID scan roots", ", ".join(coverage.roots), raw=coverage.roots),
                Fact("setid_active", "Active set-ID files", str(setid.active), raw=setid.active),
                Fact("setid_disabled", "Set-ID files disabled by mount options", str(setid.disabled), raw=setid.disabled),
            ))

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
            findings=() if status is AreaStatus.NOT_ASSESSED else tuple(findings),
            facts=tuple(facts),
            records=tuple(records),
            gaps=tuple(gaps),
        )
