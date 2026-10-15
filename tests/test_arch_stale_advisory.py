"""Regression tests for Arch advisories with stale Vulnerable status."""

import unittest
from unittest.mock import patch

from vulpnix.collectors import package_audit
from vulpnix.findings import FindingStatus
from vulpnix.models.packages import InstalledPackage, PackageInventory


class ArchStaleAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.inventory = PackageInventory(
            distribution_id="arch",
            distribution_name="Arch Linux",
            release=None,
            manager="pacman",
            packages=(InstalledPackage("pam", "1.7.3-1"),),
            status="OK",
            messages=(),
        )
        self.advisory = {
            "name": "AVG-2901",
            "packages": ["pam"],
            "status": "Vulnerable",
            "severity": "High",
            "affected": "1.7.0-2",
            "fixed": None,
            "issues": ["CVE-2025-6020"],
        }

    def audit_with_comparison(self, comparison):
        with (
            patch.object(
                package_audit,
                "_http_json",
                return_value=[self.advisory],
            ),
            patch.object(
                package_audit,
                "_version_compare_arch",
                return_value=comparison,
            ) as version_compare,
        ):
            result = package_audit._arch_tracker_audit(self.inventory)

        self.assertEqual(len(result.findings), 1)
        version_compare.assert_called_once()
        args, kwargs = version_compare.call_args
        self.assertEqual(args[:2], ("1.7.3-1", "1.7.0-2"))
        return result.findings[0]

    def test_newer_installed_version_requires_review(self):
        finding = self.audit_with_comparison(1)
        self.assertIs(finding.status, FindingStatus.REVIEW)

    def test_version_equal_to_affected_remains_fail(self):
        finding = self.audit_with_comparison(0)
        self.assertIs(finding.status, FindingStatus.FAIL)

    def test_version_older_than_affected_remains_fail(self):
        finding = self.audit_with_comparison(-1)
        self.assertIs(finding.status, FindingStatus.FAIL)

    def test_unavailable_version_comparison_requires_review(self):
        finding = self.audit_with_comparison(None)
        self.assertIs(finding.status, FindingStatus.REVIEW)

    def test_missing_affected_and_fixed_versions_requires_review(self):
        self.advisory["affected"] = None
        with (
            patch.object(
                package_audit,
                "_http_json",
                return_value=[self.advisory],
            ),
            patch.object(
                package_audit, "_version_compare_arch"
            ) as version_compare,
        ):
            result = package_audit._arch_tracker_audit(self.inventory)

        self.assertEqual(len(result.findings), 1)
        self.assertIs(result.findings[0].status, FindingStatus.REVIEW)
        version_compare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
