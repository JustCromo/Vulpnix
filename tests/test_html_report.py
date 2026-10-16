"""Tests for the self-contained HTML assessment report."""

import unittest
from dataclasses import replace

from vulpnix.cli.html_report import render_html_report, save_html_report
from vulpnix.cli.report import ReportSection, ScanReport
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.findings import (
    CVEAssessment,
    CVSSScore,
    Finding,
    FindingStatus,
)
from vulpnix.models import SystemInfo
from vulpnix.risk.engine import assess_findings


def sample_report() -> ScanReport:
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
                title="SSH",
                facts=(
                    ("Public-key authentication", "yes"),
                    ("Password authentication", "yes"),
                    ("Hostname", "test-host"),
                ),
                items=("REVIEW: Example SSH configuration needs review",),
            ),
        ),
        findings=(),
        scope=("system facts", "SSH configuration"),
    )


class HTMLReportTests(unittest.TestCase):
    def test_embeds_packaged_images_and_has_no_remote_dependencies(self):
        html = render_html_report(sample_report())

        self.assertIn("data:image/png;base64,", html)
        self.assertGreaterEqual(html.count("data:image/png;base64,"), 3)
        self.assertNotIn("https://", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("<script", html)
        self.assertIn("VULPNIX", html)
        self.assertIn("fox mascot", html)

    def test_zero_score_with_partial_coverage_is_limited_not_low(self):
        report = replace(
            sample_report(),
            findings=(),
            risk_assessment=assess_findings(()),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=3,
        )

        html = render_html_report(report)

        self.assertIn("0/25", html)
        self.assertIn("Coverage: ", html)
        self.assertIn("LIMITED", html)
        self.assertIn('class="gauge-progress gauge--limited"', html)
        self.assertIn("not proof of zero risk", html)
        self.assertIn("not converted into risk scores", html)

    def test_verified_finding_is_rendered_and_untrusted_html_is_escaped(self):
        base = sample_report()
        finding = Finding(
            rule_id="TEST-FAIL-001",
            title="<script>alert(1)</script>",
            evidence="Test evidence with <unsafe> content",
            explanation="This is a controlled finding.",
            recommendation="Review this controlled finding.",
            status=FindingStatus.FAIL,
            severity="HIGH",
            impact=4,
            probability=4,
            risk_rationale="Controlled risk rationale.",
        )
        assessment = assess_findings((finding,))
        report = replace(
            base,
            findings=(finding,),
            risk_assessment=assessment,
        )

        html = render_html_report(report)

        self.assertIn("16/25", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("TEST-FAIL-001", html)
        self.assertIn("Controlled risk rationale.", html)
        self.assertIn("Review this controlled finding.", html)
        self.assertIn("Verified issues", html)

    def test_cve_cvss_badges_are_color_coded_and_missing_scores_stay_neutral(self):
        base = sample_report()
        severity_cases = (
            ("CVE-2025-10001", "LOW", 2.9),
            ("CVE-2025-10002", "MEDIUM", 5.5),
            ("CVE-2025-10003", "HIGH", 8.1),
            ("CVE-2025-10004", "CRITICAL", 9.8),
        )
        cves = [
            CVEAssessment(
                cve_id=cve_id,
                cvss=(
                    CVSSScore(
                        version="3.1",
                        base_score=score,
                        severity=severity,
                        vector=(
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                            "S:U/C:H/I:H/A:H"
                        ),
                        source="OSV.dev",
                    ),
                ),
            )
            for cve_id, severity, score in severity_cases
        ]
        cves.append(CVEAssessment(cve_id="CVE-2025-99999"))

        finding = Finding(
            rule_id="PACKAGE-CVE-CVSS-TEST",
            title="Package vulnerability with multiple CVEs",
            evidence="Controlled test evidence.",
            explanation="Test explanation.",
            recommendation="Update the affected package.",
            status=FindingStatus.FAIL,
            severity="HIGH",
            cves=tuple(cves),
        )
        report = replace(
            base,
            findings=(finding,),
            risk_assessment=assess_findings((finding,)),
        )

        html = render_html_report(report)

        for cve_id, severity, score in severity_cases:
            with self.subTest(severity=severity):
                self.assertIn(cve_id, html)
                self.assertIn(
                    f"cvss-chip--{severity.lower()}",
                    html,
                )
                self.assertIn(f"{score:.1f} {severity}", html)

        self.assertIn("CVE-2025-99999 · CVSS unavailable", html)
        self.assertIn("cvss-chip--unknown", html)
        self.assertIn("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", html)
        self.assertIn("Source:</strong> OSV.dev", html)

    def test_area_titles_are_neutral_but_fact_values_use_semantic_status(self):
        html = render_html_report(sample_report())

        self.assertIn('<span class="area-title">SSH</span>', html)
        self.assertIn("status-value--pass", html)
        self.assertIn("status-value--review", html)
        self.assertIn("Public-key authentication", html)
        self.assertIn("Password authentication", html)

    def test_report_contains_accessible_gauge_and_responsive_print_styles(self):
        html = render_html_report(sample_report())

        self.assertIn('role="img"', html)
        self.assertIn("aria-label=", html)
        self.assertIn("@media (max-width: 760px)", html)
        self.assertIn("@media print", html)
        self.assertIn("prefers-reduced-motion", html)



class HTMLReportSaveTests(unittest.TestCase):
    def test_saves_report_with_timestamp_and_restrictive_permissions(self):
        import os
        import stat
        import tempfile
        from datetime import datetime
        from pathlib import Path

        report = sample_report()
        fixed_time = datetime(2026, 10, 16, 1, 2, 3).astimezone()

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            destination = save_html_report(
                report,
                home=home,
                generated_at=fixed_time,
            )

            self.assertEqual(destination.parent, home / "vulpnix_reports")
            self.assertEqual(
                destination.name,
                "report_scan_20261016_010203.html",
            )
            self.assertEqual(
                stat.S_IMODE(destination.parent.stat().st_mode),
                0o700,
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertIn("<!doctype html>", destination.read_text(encoding="utf-8"))

    def test_repeated_export_never_overwrites_an_existing_report(self):
        import tempfile
        from datetime import datetime
        from pathlib import Path

        report = sample_report()
        fixed_time = datetime(2026, 10, 16, 1, 2, 3).astimezone()

        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            first = save_html_report(
                report,
                area="ssh",
                home=home,
                generated_at=fixed_time,
            )
            first_content = first.read_text(encoding="utf-8")
            second = save_html_report(
                report,
                area="ssh",
                home=home,
                generated_at=fixed_time,
            )

            self.assertEqual(first.name, "report_scan_ssh_20261016_010203.html")
            self.assertEqual(second.name, "report_scan_ssh_20261016_010203_01.html")
            self.assertEqual(first.read_text(encoding="utf-8"), first_content)
            self.assertTrue(second.is_file())


if __name__ == "__main__":
    unittest.main()
