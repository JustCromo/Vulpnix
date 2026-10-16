"""Tests for distro-independent CVSS vector calculation."""

import unittest

from vulpnix.cvss import calculate_cvss


class CVSSCalculatorTests(unittest.TestCase):
    def test_calculates_cvss_v2(self):
        result = calculate_cvss(
            "AV:N/AC:L/Au:N/C:C/I:C/A:C",
            declared_type="CVSS_V2",
            source="NVD",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "2.0")
        self.assertEqual(result.base_score, 10.0)
        self.assertEqual(result.severity, "HIGH")
        self.assertEqual(result.source, "NVD")

    def test_calculates_cvss_v31(self):
        result = calculate_cvss(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            declared_type="CVSS_V3",
            source="CNA",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "3.1")
        self.assertEqual(result.base_score, 9.8)
        self.assertEqual(result.severity, "CRITICAL")
        self.assertTrue(result.vector.startswith("CVSS:3.1/"))

    def test_calculates_cvss_v4(self):
        result = calculate_cvss(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
            declared_type="CVSS_V4",
        )
        self.assertIsNotNone(result)
        self.assertEqual(result.version, "4.0")
        self.assertEqual(result.base_score, 9.9)
        self.assertEqual(result.severity, "CRITICAL")

    def test_missing_or_malformed_vectors_are_not_scored(self):
        for vector in (None, "", "not-a-cvss-vector", "CVSS:3.1/invalid"):
            with self.subTest(vector=vector):
                self.assertIsNone(calculate_cvss(vector))

    def test_declared_type_must_match_vector_version(self):
        self.assertIsNone(
            calculate_cvss(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                declared_type="CVSS_V4",
            )
        )

    def test_unknown_vector_format_is_not_guessed(self):
        self.assertIsNone(calculate_cvss("AV:N/AC:L/Au:N/C:C/I:C/A:C", declared_type="CVSS_V3"))

    def test_source_metadata_is_optional(self):
        result = calculate_cvss(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            declared_type="CVSS_V3",
        )
        self.assertIsNotNone(result)
        self.assertIsNone(result.source)


if __name__ == "__main__":
    unittest.main()
