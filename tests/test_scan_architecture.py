import unittest

from vulpnix.cli.report import ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.scan.orchestrator import ScanOrchestrator
from vulpnix.scan.result import ScanResult


class ScanArchitectureTests(unittest.TestCase):
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
        result = ScanOrchestrator().run_full_scan(
            services_result=lambda: ScanResult(sections=(ReportSection("SERVICES"),)),
            users_result=lambda: ScanResult(sections=(ReportSection("USERS"),)),
            filesystem_section_builder=lambda *_: ReportSection("FILESYSTEM"),
            sensitive_file_collector=lambda: (),
            sensitive_file_assessor=lambda _: __import__("vulpnix.rules.filesystem", fromlist=["FilesystemAssessment"]).FilesystemAssessment((), (), ()),
            setid_collector=lambda: __import__("vulpnix.models", fromlist=["FilesystemCoverage", "CoverageStatus"]).FilesystemCoverage((), __import__("vulpnix.models", fromlist=["CoverageStatus"]).CoverageStatus.COLLECTED, ("/usr",), 0, 0.0),
            setid_assessor=lambda _: __import__("vulpnix.rules.filesystem", fromlist=["SetIdAssessment"]).SetIdAssessment(0, 0, 0, (), ()),
        )
        self.assertEqual([section.title for section in result.sections], ["SERVICES", "USERS", "FILESYSTEM"])
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
