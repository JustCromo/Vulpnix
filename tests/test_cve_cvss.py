"""Tests for the structured CVE and CVSS finding models."""

import math
import unittest

from vulpnix.findings import (
    CVEAssessment,
    CVSSScore,
    Finding,
    FindingStatus,
)


class CVEModelTests(unittest.TestCase):
    def test_cve_can_keep_multiple_cvss_assessments(self):
        cvss31 = CVSSScore(
            version="3.1",
            base_score=8.8,
            severity="HIGH",
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            source="NVD",
        )
        cvss40 = CVSSScore(
            version="4.0",
            base_score=9.3,
            severity="CRITICAL",
            vector=(
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                "VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
            ),
            source="CNA",
        )

        cve = CVEAssessment(
            cve_id="CVE-2025-12345",
            cvss=(cvss31, cvss40),
        )

        self.assertEqual(cve.cve_id, "CVE-2025-12345")
        self.assertEqual(len(cve.cvss), 2)
        self.assertEqual(cve.cvss[0].base_score, 8.8)
        self.assertEqual(cve.cvss[1].version, "4.0")
        self.assertEqual(cve.cvss[1].source, "CNA")

    def test_existing_findings_default_to_no_cve_metadata(self):
        finding = Finding(
            rule_id="TEST-RULE",
            title="Test finding",
            evidence="Test evidence",
            explanation="Test explanation",
            recommendation="Test recommendation",
            status=FindingStatus.REVIEW,
        )

        self.assertEqual(finding.cves, ())

    def test_cvss_score_rejects_values_outside_valid_range(self):
        for invalid_score in (-0.1, 10.1, math.inf, math.nan):
            with self.subTest(score=invalid_score):
                with self.assertRaises(ValueError):
                    CVSSScore(
                        version="3.1",
                        base_score=invalid_score,
                        severity="HIGH",
                        vector="CVSS:3.1/example",
                    )

    def test_cvss_requires_version_severity_and_vector(self):
        for field, value in (
            ("version", ""),
            ("severity", ""),
            ("vector", ""),
        ):
            values = {
                "version": "3.1",
                "base_score": 5.0,
                "severity": "MEDIUM",
                "vector": "CVSS:3.1/example",
            }
            values[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    CVSSScore(**values)


if __name__ == "__main__":
    unittest.main()
