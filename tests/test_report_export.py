"""Tests for Markdown and JSON report exports."""

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from vulpnix.cli.report import ReportSection, ScanReport
from vulpnix.cli.report_export import (
    render_json_report,
    render_markdown_report,
    save_report_export,
)
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.findings import CVEAssessment, CVSSScore, Finding, FindingStatus
from vulpnix.models import SystemInfo
from vulpnix.risk.engine import assess_findings


def sample_report() -> ScanReport:
    finding = Finding(
        rule_id="PACKAGE-CVE-2026-12345",
        title="Package | advisory requires review",
        evidence="Installed version needs review.",
        explanation="Available source data does not confirm exploitation.",
        recommendation="Review the advisory and update guidance.",
        status=FindingStatus.REVIEW,
        severity="MEDIUM",
        cves=(
            CVEAssessment(
                cve_id="CVE-2026-12345",
                cvss=(
                    CVSSScore(
                        version="3.1",
                        base_score=5.5,
                        severity="MEDIUM",
                        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        source="NVD (cve@vendor.example; nvd@nist.gov)",
                    ),
                ),
            ),
        ),
    )

    return ScanReport(
        host=SystemInfo(
            hostname="test-host",
            distribution="Example Linux",
            distribution_version="1.0",
            kernel_release="6.1-test",
            architecture="x86_64",
            uptime_seconds=3600,
        ),
        sections=(
            ReportSection(
                title="SERVICES",
                facts=(
                    ("Units", "342"),
                    ("Startup enabled", "12 yes · 102 no · 205 non-boolean · 23 unknown"),
                ),
                items=("REVIEW: Example service needs review",),
            ),
        ),
        findings=(finding,),
        scope=("service inventory", "package vulnerability audit"),
        coverage=AssessmentCoverage.COMPLETE,
        review_items=0,
        risk_assessment=assess_findings((finding,)),
    )


class ReportExportTests(unittest.TestCase):
    def test_json_is_valid_and_preserves_assessment_and_cvss_data(self):
        report = sample_report()

        data = json.loads(
            render_json_report(
                report,
                generated_at=datetime(2026, 10, 16, 12, 30, 0).astimezone(),
            )
        )

        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["tool"], "Vulpnix")
        self.assertEqual(data["host"]["hostname"], "test-host")
        self.assertEqual(data["coverage"]["observed"], "COMPLETE")
        self.assertEqual(data["coverage"]["status"], "LIMITED")
        self.assertEqual(data["coverage"]["findings_to_review"], 1)
        self.assertEqual(data["coverage"]["additional_review_items"], 0)
        self.assertEqual(data["coverage"]["total_review_items"], 1)

        finding = data["findings"][0]
        self.assertEqual(finding["status"], "REVIEW")
        self.assertEqual(finding["rule_id"], "PACKAGE-CVE-2026-12345")
        self.assertEqual(finding["cves"][0]["cve_id"], "CVE-2026-12345")
        score = finding["cves"][0]["cvss"][0]
        self.assertEqual(score["base_score"], 5.5)
        self.assertEqual(score["severity"], "MEDIUM")
        self.assertEqual(score["source"], "NVD (cve@vendor.example; nvd@nist.gov)")
        self.assertEqual(len(finding["cves"][0]["cvss"]), 1)

        service_facts = {
            item["label"]: item["value"]
            for item in data["sections"][0]["facts"]
        }
        self.assertEqual(
            service_facts["Startup enabled"],
            "12 yes · 102 no · 205 non-boolean · 23 unknown",
        )

    def test_markdown_contains_findings_cvss_scope_and_service_details(self):
        markdown = render_markdown_report(sample_report())

        self.assertIn("# Vulpnix Security Report", markdown)
        self.assertIn("## Assessment overview", markdown)
        self.assertIn("## Findings", markdown)
        self.assertIn("REVIEW REQUIRED", markdown)
        self.assertIn("LIMITED", markdown)
        self.assertIn("test-host", markdown)
        self.assertIn(r"Package \| advisory requires review", markdown)
        self.assertIn("CVE-2026-12345", markdown)
        self.assertIn("CVSS 3.1", markdown)
        self.assertIn("5.5 (MEDIUM)", markdown)
        self.assertIn("NVD (cve@vendor.example; nvd@nist.gov)", markdown)
        self.assertIn(
            "`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`",
            markdown,
        )
        self.assertIn("205 non-boolean · 23 unknown", markdown)
        self.assertIn("finding scores are not summed", markdown.lower())

    def test_exports_use_private_permissions_and_never_overwrite(self):
        report = sample_report()
        fixed_time = datetime.now().astimezone().replace(microsecond=0)

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)

            markdown_path = save_report_export(
                report,
                "markdown",
                area="packages",
                home=home,
                generated_at=fixed_time,
            )
            json_path = save_report_export(
                report,
                "json",
                area="packages",
                home=home,
                generated_at=fixed_time,
            )

            self.assertEqual(markdown_path.suffix, ".md")
            self.assertEqual(json_path.suffix, ".json")
            self.assertTrue(markdown_path.is_file())
            self.assertTrue(json_path.is_file())

            reports_dir = home / "vulpnix_reports"
            self.assertEqual(stat.S_IMODE(reports_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(markdown_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(json_path.stat().st_mode), 0o600)

            original = markdown_path.read_text(encoding="utf-8")
            second_path = save_report_export(
                report,
                "markdown",
                area="packages",
                home=home,
                generated_at=fixed_time,
            )

            self.assertNotEqual(markdown_path, second_path)
            self.assertTrue(second_path.name.endswith("_01.md"))
            self.assertEqual(markdown_path.read_text(encoding="utf-8"), original)
            self.assertEqual(
                json.loads(json_path.read_text(encoding="utf-8"))["tool"],
                "Vulpnix",
            )


if __name__ == "__main__":
    unittest.main()
