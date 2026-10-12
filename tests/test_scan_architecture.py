import unittest
from unittest.mock import Mock

from vulpnix.cli.report import ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.models import SystemInfo
from vulpnix.scan.orchestrator import ScanOrchestrator
from vulpnix.scan.progress import ScanStage
from vulpnix.scan.privilege import PrivilegeContext


class ScanArchitectureTests(unittest.TestCase):
    def test_users_lifecycle_is_ordered_and_returns_privilege_context(self):
        events = []
        collector = Mock(return_value=())
        sudo = Mock(return_value=())
        builder = Mock(return_value=ReportSection("USERS"))
        result = ScanOrchestrator(progress_callback=events.append).run_users(
            users_collector=collector,
            sudo_collector=sudo,
            section_builder=builder,
        )
        self.assertEqual(
            [event.stage for event in events],
            [ScanStage.STARTING, ScanStage.COLLECTING, ScanStage.COLLECTING, ScanStage.ASSESSING, ScanStage.COMPLETED],
        )
        self.assertIsInstance(result.privilege, PrivilegeContext)
        self.assertEqual(result.sections[0].title, "USERS")

    def test_filesystem_partial_coverage_requires_review(self):
        from vulpnix.models import CoverageStatus, FilesystemCoverage
        from vulpnix.rules.filesystem import FilesystemAssessment, SetIdAssessment
        coverage = FilesystemCoverage((), CoverageStatus.PARTIAL, ("/usr",), 3, 0.1, ("permission denied",))
        orchestrator = ScanOrchestrator()
        result = orchestrator.run_filesystem(
            sensitive_file_collector=lambda: (),
            sensitive_file_assessor=lambda _: FilesystemAssessment((), (), ()),
            setid_collector=lambda: coverage,
            setid_assessor=lambda _: SetIdAssessment(0, 0, 0, ("permission denied",), ()),
            section_builder=lambda *_: ReportSection("FILESYSTEM"),
        )
        self.assertEqual(result.coverage, AssessmentCoverage.PARTIAL)
        self.assertGreater(result.review_items, 0)

    def test_full_scan_has_all_sections_and_final_coverage(self):
        system = SystemInfo("host", "Linux", "1", "kernel", "x86_64", 60)
        result = ScanOrchestrator().run_full_scan(
            host_collector=lambda: system,
            host_section_builder=lambda info: ReportSection("SYSTEM"),
            service_section_builder=lambda _: ReportSection("SERVICES"),
            users_section_builder=lambda *_: ReportSection("USERS"),
            filesystem_section_builder=lambda *_: ReportSection("FILESYSTEM"),
            ssh_section_builder=lambda _: ReportSection("SSH"),
            ssh_findings_builder=lambda _: (),
            services_collector=lambda: (),
            users_collector=lambda: (),
            sudo_collector=lambda _: (),
            sensitive_file_collector=lambda: (),
            sensitive_file_assessor=lambda _: __import__("vulpnix.rules.filesystem", fromlist=["FilesystemAssessment"]).FilesystemAssessment((), (), ()),
            setid_collector=lambda: __import__("vulpnix.models", fromlist=["FilesystemCoverage", "CoverageStatus"]).FilesystemCoverage((), __import__("vulpnix.models", fromlist=["CoverageStatus"]).CoverageStatus.COLLECTED, ("/usr",), 0, 0.0),
            setid_assessor=lambda _: __import__("vulpnix.rules.filesystem", fromlist=["SetIdAssessment"]).SetIdAssessment(0, 0, 0, (), ()),
            ssh_collector=lambda: None,
        )
        self.assertEqual([section.title for section in result.sections], ["SYSTEM", "SERVICES", "USERS", "FILESYSTEM", "SSH"])
        self.assertEqual(result.coverage, AssessmentCoverage.COMPLETE)
        self.assertEqual(result.review_items, 0)


if __name__ == "__main__":
    unittest.main()

class PrivilegeModeTests(unittest.TestCase):
    def test_rootless_filesystem_result_requests_elevation(self):
        from unittest.mock import patch
        from vulpnix.cli import report
        from vulpnix.models import CoverageStatus, FilesystemCoverage
        from vulpnix.rules.filesystem import FilesystemAssessment, SetIdAssessment

        coverage = FilesystemCoverage((), CoverageStatus.PARTIAL, ("/usr",), 1, 0.1, ("permission denied",))
        with patch("vulpnix.scan.privilege.os.geteuid", return_value=1000):
            result = ScanOrchestrator().run_filesystem(
                sensitive_file_collector=lambda: (),
                sensitive_file_assessor=lambda _: FilesystemAssessment((), (), ()),
                setid_collector=lambda: coverage,
                setid_assessor=lambda _: SetIdAssessment(0, 0, 0, ("permission denied",), ()),
                section_builder=lambda *_: ReportSection("FILESYSTEM"),
            )
        self.assertEqual(result.privilege.mode, "ROOTLESS")
        self.assertEqual(result.coverage, AssessmentCoverage.PARTIAL)
        rendered = report.render_scan_report(
            report.ScanReport(
                host=None,
                sections=result.sections,
                findings=result.findings,
                scope=result.scope,
                coverage=result.coverage,
                review_items=result.review_items,
                privilege=result.privilege,
            ),
            80,
        )
        text = "\n".join(rendered)
        self.assertIn("REVIEW REQUIRED", text)
        self.assertIn("current privileges", text)
        self.assertIn("sudo vulpnix", text)
