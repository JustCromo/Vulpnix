"""Tests for per-CVE CVSS output in package audit details."""

import unittest

from vulpnix.cli.app import _package_audit_report_section
from vulpnix.findings import (
    CVEAssessment,
    CVSSScore,
    Finding,
    FindingStatus,
)
from vulpnix.models.packages import PackageAudit


class PackageCVSSCliTests(unittest.TestCase):
    def make_audit(self):
        scored_cve = CVEAssessment(
            cve_id="CVE-2025-12345",
            cvss=(
                CVSSScore(
                    version="3.1",
                    base_score=9.8,
                    severity="CRITICAL",
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    source="NVD (test)",
                ),
            ),
        )
        unscored_cve = CVEAssessment(cve_id="CVE-2025-67890")

        finding = Finding(
            rule_id="PACKAGE-CVE-TEST-DEMO",
            title="demo 1.0 affected by CVEs",
            evidence="Test package advisory evidence",
            explanation="Test finding for CVSS presentation",
            recommendation="Update the affected package",
            status=FindingStatus.FAIL,
            severity="HIGH",
            impact=4,
            probability=3,
            risk_rationale="Test rationale",
            cves=(scored_cve, unscored_cve),
        )

        return PackageAudit(
            source="Test advisory source",
            status="OK",
            packages_checked=1,
            findings=(finding,),
            messages=(),
        )

    def test_details_include_cvss_score_source_vector_and_missing_score(self):
        section = _package_audit_report_section(self.make_audit(), details=True)
        output = "\\n".join(section.items)

        self.assertIn("CVE-2025-12345: CVSS 3.1 9.8 — CRITICAL", output)
        self.assertIn("Source: NVD (test)", output)
        self.assertIn(
            "Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            output,
        )
        self.assertIn("CVE-2025-67890: CVSS unavailable", output)

    def test_summary_does_not_expand_cvss_details(self):
        section = _package_audit_report_section(self.make_audit(), details=False)
        output = "\\n".join(section.items)

        self.assertIn("PACKAGE-CVE-TEST-DEMO", output)
        self.assertNotIn("CVSS 3.1", output)
        self.assertNotIn("CVSS unavailable", output)


if __name__ == "__main__":
    unittest.main()
