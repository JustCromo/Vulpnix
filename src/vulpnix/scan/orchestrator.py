from __future__ import annotations

from collections.abc import Callable
import subprocess

from vulpnix.cli.report import ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.collectors import (
    collect_local_users,
    collect_services,
    collect_setid_files,
    collect_sensitive_file_metadata,
    collect_sudo_privileges,
    collect_system_info,
)
from vulpnix.collectors.hardening import collect_sysctl_observations
from vulpnix.collectors.network import collect_network_snapshot
from vulpnix.collectors.ssh_keys import collect_ssh_host_key_metadata
from vulpnix.collectors.systemd_security import collect_service_unit_file_metadata
from vulpnix.findings import Finding
from vulpnix.collectors.ssh import SSHCommandError, SSHGUnsupportedError
from vulpnix.models import (
    FileMetadataResult,
    FilesystemCoverage,
    SSHConfig,
    Service,
    SudoPrivilege,
    SudoPrivilegeStatus,
    SystemInfo,
    User,
    HardeningAssessment,
    NetworkSnapshot,
    SSHHostKeyAssessment,
    SSHHostKeyObservation,
    UnitFileAssessment,
    UnitFileObservation,
)
from vulpnix.rules.filesystem import (
    FilesystemAssessment,
    SetIdAssessment,
    assess_sensitive_files,
    assess_setid_files,
)
from vulpnix.rules.hardening import assess_kernel_hardening
from vulpnix.rules.ssh_keys import assess_ssh_host_key_metadata
from vulpnix.rules.systemd_security import assess_systemd_unit_metadata
from vulpnix.scan.privilege import current_privilege_context
from vulpnix.scan.progress import ScanProgress, ScanStage
from vulpnix.scan.result import ScanResult

UsersCollector = Callable[[], tuple[User, ...]]
SudoCollector = Callable[[tuple[User, ...]], tuple[SudoPrivilege, ...]]
SSHCollector = Callable[[], SSHConfig]
HostCollector = Callable[[], SystemInfo]
ServicesCollector = Callable[[], tuple[Service, ...]]
UsersSectionBuilder = Callable[[tuple[User, ...], tuple[SudoPrivilege, ...]], ReportSection]
SSHSectionBuilder = Callable[[SSHConfig], ReportSection]
SSHFindingsBuilder = Callable[[SSHConfig], tuple[Finding, ...]]
FilesystemSectionBuilder = Callable[
    [tuple[FileMetadataResult, ...], FilesystemAssessment, FilesystemCoverage, SetIdAssessment],
    ReportSection,
]
ServiceSectionBuilder = Callable[[tuple[Service, ...]], ReportSection]
HostSectionBuilder = Callable[[SystemInfo], ReportSection]
HardeningSectionBuilder = Callable[[HardeningAssessment], ReportSection]
NetworkSectionBuilder = Callable[[NetworkSnapshot], ReportSection]
SSHHostKeySectionBuilder = Callable[[SSHHostKeyAssessment], ReportSection]
UnitFileSectionBuilder = Callable[[UnitFileAssessment], ReportSection]


class ScanOrchestrator:
    """Run scans as a shared lifecycle: progress -> collection -> assessment -> result."""

    def __init__(self, *, progress_callback: Callable[[ScanProgress], None] | None = None) -> None:
        self._progress_callback = progress_callback
        self._privilege = current_privilege_context()

    def _emit(self, stage: ScanStage, message: str, *, completed: int = 0, total: int | None = None) -> None:
        if self._progress_callback is not None:
            self._progress_callback(ScanProgress(stage, message, completed, total))

    def _result(self, **kwargs: object) -> ScanResult:
        return ScanResult(privilege=self._privilege, **kwargs)

    @staticmethod
    def _user_review_items(users: tuple[User, ...], sudo: tuple[SudoPrivilege, ...]) -> int:
        return sum(user.groups is None or user.account_state is None for user in users) + sum(
            result.status in {SudoPrivilegeStatus.UNAVAILABLE, SudoPrivilegeStatus.NOT_ASSESSED}
            for result in sudo
        )

    @staticmethod
    def _service_review_items(services: tuple[Service, ...]) -> int:
        return sum(service.enabled is None or service.state in {"unknown", ""} for service in services)

    def run_host(self, *, collector: HostCollector = collect_system_info, section_builder: HostSectionBuilder) -> ScanResult:
        self._emit(ScanStage.STARTING, "Starting host assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Collecting host facts")
            info = collector()
            self._emit(ScanStage.ASSESSING, "Building host report")
            section = section_builder(info)
        except (OSError, UnicodeError, ValueError, NotImplementedError) as error:
            self._emit(ScanStage.ERROR, f"Host assessment failed: {error}")
            raise
        self._emit(ScanStage.COMPLETED, "Host assessment completed")
        return self._result(sections=(section,), scope=("system facts",), host=info)

    def run_services(self, *, collector: ServicesCollector = collect_services, section_builder: ServiceSectionBuilder) -> ScanResult:
        self._emit(ScanStage.STARTING, "Starting services assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Collecting services")
            services = collector()
            self._emit(ScanStage.ASSESSING, "Assessing service state")
            section = section_builder(services)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
            self._emit(ScanStage.ERROR, f"Services assessment failed: {error}")
            raise
        self._emit(ScanStage.COMPLETED, "Services assessment completed")
        review_items = self._service_review_items(services)
        return self._result(
            sections=(section,),
            scope=("services",),
            coverage=AssessmentCoverage.PARTIAL if review_items else AssessmentCoverage.COMPLETE,
            review_items=review_items,
        )

    def run_users(self, *, section_builder: UsersSectionBuilder, users_collector: UsersCollector = collect_local_users, sudo_collector: SudoCollector = collect_sudo_privileges) -> ScanResult:
        self._emit(ScanStage.STARTING, "Starting users assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Collecting local accounts")
            users = users_collector()
            self._emit(ScanStage.COLLECTING, "Collecting privilege information")
            sudo_privileges = sudo_collector(users)
            self._emit(ScanStage.ASSESSING, "Assessing users and privileges")
            section = section_builder(users, sudo_privileges)
        except (OSError, UnicodeError, ValueError) as error:
            self._emit(ScanStage.ERROR, f"Users assessment failed: {error}")
            raise
        self._emit(ScanStage.COMPLETED, "Users assessment completed")
        review_items = self._user_review_items(users, sudo_privileges)
        return self._result(
            sections=(section,),
            scope=("users", "privileges"),
            coverage=AssessmentCoverage.PARTIAL if review_items else AssessmentCoverage.COMPLETE,
            review_items=review_items,
        )

    def run_ssh(self, *, section_builder: SSHSectionBuilder, findings_builder: SSHFindingsBuilder, ssh_collector: SSHCollector) -> ScanResult:
        self._emit(ScanStage.STARTING, "Starting SSH assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Collecting SSH configuration")
            config = ssh_collector()
            self._emit(ScanStage.ASSESSING, "Assessing SSH configuration")
            section = section_builder(config)
            findings = findings_builder(config)
        except (OSError, UnicodeError, ValueError) as error:
            self._emit(ScanStage.ERROR, f"SSH assessment failed: {error}")
            raise
        self._emit(ScanStage.COMPLETED, "SSH assessment completed")
        return self._result(sections=(section,), findings=findings, scope=("SSH configuration",))

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

    def run_hardening(
        self,
        *,
        section_builder: HardeningSectionBuilder,
        collector: Callable[[], tuple] = collect_sysctl_observations,
    ) -> ScanResult:
        """Collect and assess a fixed allow-list of read-only kernel parameters."""
        self._emit(ScanStage.STARTING, "Starting kernel hardening assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Reading selected kernel parameters")
            observations = collector()
            self._emit(ScanStage.ASSESSING, "Assessing kernel hardening settings")
            assessment = assess_kernel_hardening(observations)
            section = section_builder(assessment)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
            self._emit(ScanStage.ERROR, f"Kernel hardening assessment failed: {error}")
            raise
        self._emit(ScanStage.COMPLETED, "Kernel hardening assessment completed")
        unresolved_findings = sum(
            finding.status.name in {"NOT_ASSESSED", "ERROR"}
            for finding in assessment.findings
        )
        return self._result(
            sections=(section,),
            findings=assessment.findings,
            scope=("kernel hardening",),
            coverage=AssessmentCoverage.PARTIAL if assessment.incomplete_checks else AssessmentCoverage.COMPLETE,
            review_items=max(0, assessment.incomplete_checks - unresolved_findings),
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

    def run_ssh_host_keys(
        self,
        *,
        section_builder: SSHHostKeySectionBuilder,
        collector: Callable[[], tuple[SSHHostKeyObservation, ...]] = collect_ssh_host_key_metadata,
    ) -> ScanResult:
        """Assess SSH host-key ownership and modes without reading key material."""
        self._emit(ScanStage.STARTING, "Starting SSH host-key metadata assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Inspecting SSH host-key metadata")
            observations = collector()
            self._emit(ScanStage.ASSESSING, "Assessing key ownership and permissions")
            assessment = assess_ssh_host_key_metadata(observations)
            section = section_builder(assessment)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
            self._emit(ScanStage.ERROR, f"SSH host-key assessment failed: {error}")
            raise
        self._emit(ScanStage.COMPLETED, "SSH host-key metadata assessment completed")
        incomplete = assessment.incomplete_checks
        unresolved = sum(finding.status.name in {"NOT_ASSESSED", "ERROR"} for finding in assessment.findings)
        return self._result(
            sections=(section,),
            findings=assessment.findings,
            scope=("SSH host-key metadata",),
            coverage=AssessmentCoverage.PARTIAL if incomplete else AssessmentCoverage.COMPLETE,
            review_items=max(0, incomplete - unresolved),
        )

    def run_service_unit_security(
        self,
        *,
        services: tuple[Service, ...],
        section_builder: UnitFileSectionBuilder,
        collector: Callable[[tuple[Service, ...]], tuple[tuple[UnitFileObservation, ...], tuple[str, ...]]] = collect_service_unit_file_metadata,
    ) -> ScanResult:
        """Inspect service fragment and drop-in metadata without opening file contents."""
        self._emit(ScanStage.STARTING, "Starting systemd unit-file assessment")
        try:
            self._emit(ScanStage.COLLECTING, "Collecting unit fragment/drop-in metadata")
            observations, collection_review = collector(services)
            self._emit(ScanStage.ASSESSING, "Checking unit ownership and write permissions")
            assessment = assess_systemd_unit_metadata(observations, collection_review)
            section = section_builder(assessment)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
            self._emit(ScanStage.ERROR, f"Systemd unit-file assessment failed: {error}")
            raise
        self._emit(ScanStage.COMPLETED, "Systemd unit-file assessment completed")
        incomplete = assessment.incomplete_checks or bool(collection_review)
        unresolved_findings = sum(finding.status.name in {"NOT_ASSESSED", "ERROR"} for finding in assessment.findings)
        extra_reviews = max(0, len(collection_review) - unresolved_findings)
        return self._result(
            sections=(section,),
            findings=assessment.findings,
            scope=("systemd unit-file metadata",),
            coverage=AssessmentCoverage.PARTIAL if incomplete else AssessmentCoverage.COMPLETE,
            review_items=extra_reviews,
        )

    def run_full_scan(
        self,
        *,
        users_section_builder: UsersSectionBuilder,
        filesystem_section_builder: FilesystemSectionBuilder,
        ssh_section_builder: SSHSectionBuilder,
        ssh_findings_builder: SSHFindingsBuilder,
        service_section_builder: ServiceSectionBuilder,
        host_section_builder: HostSectionBuilder,
        host_collector: HostCollector = collect_system_info,
        services_collector: ServicesCollector = collect_services,
        users_collector: UsersCollector = collect_local_users,
        sudo_collector: SudoCollector = collect_sudo_privileges,
        sensitive_file_collector: Callable[[], tuple[FileMetadataResult, ...]] = collect_sensitive_file_metadata,
        sensitive_file_assessor: Callable[[tuple[FileMetadataResult, ...]], FilesystemAssessment] = assess_sensitive_files,
        setid_collector: Callable[[], FilesystemCoverage] = collect_setid_files,
        setid_assessor: Callable[[FilesystemCoverage], SetIdAssessment] = assess_setid_files,
        ssh_collector: SSHCollector,
    ) -> ScanResult:
        self._emit(ScanStage.STARTING, "Starting full Linux assessment", total=9)
        sections: list[ReportSection] = []
        findings: list[Finding] = []
        review_items = 0

        self._emit(ScanStage.COLLECTING, "Collecting host facts", completed=1, total=9)
        host = host_collector()
        sections.append(host_section_builder(host))

        try:
            self._emit(ScanStage.COLLECTING, "Collecting services", completed=2, total=9)
            services = services_collector()
            sections.append(service_section_builder(services))
            review_items += self._service_review_items(services)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
            sections.append(ReportSection("SERVICES", status="NOT_ASSESSED", message="Service information could not be collected with the current capabilities."))
            review_items += 1

        try:
            self._emit(ScanStage.COLLECTING, "Collecting local accounts", completed=3, total=9)
            users = users_collector()
            self._emit(ScanStage.COLLECTING, "Collecting privilege information", completed=4, total=9)
            sudo = sudo_collector(users)
            sections.append(users_section_builder(users, sudo))
            review_items += self._user_review_items(users, sudo)
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
            sections.append(ReportSection("USERS", status="NOT_ASSESSED", message="User and privilege information could not be fully collected."))
            review_items += 1

        try:
            self._emit(ScanStage.COLLECTING, "Collecting sensitive file metadata", completed=5, total=9)
            file_results = sensitive_file_collector()
            self._emit(ScanStage.ASSESSING, "Assessing sensitive file metadata", completed=6, total=9)
            fs_assessment = sensitive_file_assessor(file_results)
            self._emit(ScanStage.COLLECTING, "Collecting set-ID files", completed=7, total=9)
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

        try:
            self._emit(ScanStage.COLLECTING, "Collecting SSH configuration", completed=8, total=9)
            config = ssh_collector()
            self._emit(ScanStage.ASSESSING, "Assessing SSH configuration", completed=9, total=9)
            sections.append(ssh_section_builder(config))
            findings.extend(ssh_findings_builder(config))
        except (OSError, UnicodeError, ValueError, SSHCommandError) as error:
            if isinstance(error, SSHCommandError):
                detail = "".join(ch if ch.isprintable() else "�" for ch in error.diagnostic)
                if isinstance(error, SSHGUnsupportedError):
                    message = f"sshd {error.option} is not supported by this OpenSSH installation (exit {error.returncode}: {detail})"
                else:
                    message = f"sshd {error.option} failed (exit {error.returncode}: {detail})"
            else:
                message = str(error) or "SSH configuration is unavailable."
            sections.append(ReportSection("SSH", status="NOT_ASSESSED", message=message))
            review_items += 1

        coverage = AssessmentCoverage.PARTIAL if review_items else AssessmentCoverage.COMPLETE
        self._emit(ScanStage.COMPLETED, "Full Linux assessment completed", completed=9, total=9)
        return self._result(
            host=host,
            sections=tuple(sections),
            findings=tuple(findings),
            scope=("system facts", "users", "services", "SSH configuration", "filesystem metadata", "set-ID files"),
            coverage=coverage,
            review_items=review_items,
        )
