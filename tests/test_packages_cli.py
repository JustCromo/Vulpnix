"""CLI tests for software inventory and CVE integration."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix.findings import Finding, FindingStatus
from vulpnix.models.packages import InstalledPackage, PackageAudit, PackageInventory


class PackageCliTests(unittest.TestCase):
    def inventory(self):
        return PackageInventory(
            distribution_id="debian",
            distribution_name="Debian GNU/Linux",
            release="12",
            manager="dpkg-query",
            packages=(InstalledPackage("demo", "1.0-1", "amd64"),),
            status="OK",
        )


    def test_package_scan_runs_inventory_and_cve_audit_by_default(self):
        output = io.StringIO()
        audit_result = PackageAudit(
            source="Test advisory source",
            status="OK",
            packages_checked=1,
        )

        with (
            patch.object(
                app, "collect_package_inventory", return_value=self.inventory()
            ),
            patch.object(
                app, "collect_package_audit", return_value=audit_result
            ) as audit,
            redirect_stdout(output),
        ):
            app._dispatch_command("scan packages")

        audit.assert_called_once()
        report = output.getvalue()
        self.assertIn("SOFTWARE INVENTORY", report)
        self.assertIn("PACKAGE VULNERABILITY AUDIT", report)
        self.assertIn("Test advisory source", report)
        self.assertIn("Installed packages: 1", report)
        self.assertNotIn("demo", report)
        self.assertIn("dpkg-query", report)

    def test_package_scan_renders_finding_and_risk(self):
        finding = Finding(
            rule_id="PACKAGE-CVE-CVE-2025-12345-DEMO",
            title="demo 1.0-1 affected by CVE-2025-12345",
            evidence="Installed package demo 1.0-1 matched advisory CVE-2025-12345",
            explanation="The advisory source marks this installed package version as affected.",
            recommendation="Install the fixed distribution package.",
            status=FindingStatus.FAIL,
            severity="HIGH",
            impact=4,
            probability=3,
            risk_rationale="Impact 4 and qualitative probability 3 based on advisory severity.",
        )
        audit_result = PackageAudit(
            source="Test advisory source",
            status="OK",
            packages_checked=1,
            findings=(finding,),
        )
        output = io.StringIO()

        with (
            patch.object(app, "collect_package_inventory", return_value=self.inventory()),
            patch.object(app, "collect_package_audit", return_value=audit_result),
            redirect_stdout(output),
        ):
            app._dispatch_command("scan packages --details")

        report = output.getvalue()
        self.assertIn("PACKAGE VULNERABILITY AUDIT", report)
        self.assertIn("CVE-2025-12345", report)
        self.assertIn("RISK ASSESSMENT", report)
        self.assertRegex(report, r"IMPACT\s+PROB\.\s+SCORE\s+LEVEL")
        self.assertRegex(
            report,
            r"PACKAGE-CVE-CVE-2025-12345-DEMO\s+4\s+3\s+12\s+HIGH",
        )
        self.assertIn("HIGH", report)


    def test_full_scan_runs_without_cve_flag(self):
        with patch.object(app, "_show_scan") as scan:
            app._dispatch_command("scan")
        scan.assert_called_once_with(detailed=False)

    def test_full_scan_details_flag_is_forwarded(self):
        with patch.object(app, "_show_scan") as scan:
            app._dispatch_command("scan --details")
        scan.assert_called_once_with(detailed=True)

    def test_removed_cve_flags_are_rejected(self):
        for command in ("scan --cve", "scan packages --cve"):
            with self.subTest(command=command):
                output = io.StringIO()
                with (
                    patch.object(app, "_show_scan") as scan,
                    patch.object(app, "_show_packages_assessment") as packages,
                    redirect_stdout(output),
                ):
                    app._dispatch_command(command)

                self.assertIn("Usage: scan", output.getvalue())
                scan.assert_not_called()
                packages.assert_not_called()

    def test_package_commands_are_available_in_completion(self):
        completions = app._command_completions("scan packages")
        self.assertIn("scan packages", completions)
        self.assertIn("scan packages --details", completions)
        self.assertFalse(any("--cve" in command for command in completions))

if __name__ == "__main__":
    unittest.main()
