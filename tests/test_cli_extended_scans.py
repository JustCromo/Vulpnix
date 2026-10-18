"""User-visible tests for the expanded scan commands and compact/detail modes."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix.areas.hardening import area as hardening_area
from vulpnix.areas.host import area as host_area
from vulpnix.areas.ssh import area as ssh_area
from vulpnix.areas.ssh import host_keys as ssh_host_keys_area
from vulpnix.findings import FindingStatus
from vulpnix.models import (
    ListeningEndpoint,
    NetworkInterface,
    NetworkInterfaceSnapshot,
    NetworkSnapshot,
    SSHConfig,
    SSHHostKeyObservation,
    Service,
    SysctlObservation,
    UnitFileAssessment,
    UnitFileCheck,
    UnitFileObservation,
)
from vulpnix.scan.privilege import PrivilegeContext


class ExtendedScanCommandTests(unittest.TestCase):
    def test_hardening_default_is_compact_and_details_expands_checks(self):
        observations = (SysctlObservation("kernel.dmesg_restrict", "1"),)
        compact = io.StringIO()
        with patch.object(hardening_area, "collect_sysctl_observations", return_value=observations), redirect_stdout(compact):
            app._dispatch_command("scan hardening")
        detailed = io.StringIO()
        with patch.object(hardening_area, "collect_sysctl_observations", return_value=observations), redirect_stdout(detailed):
            app._dispatch_command("scan hardening --details")

        self.assertIn("KERNEL HARDENING", compact.getvalue())
        self.assertIn("Checks passing", compact.getvalue())
        self.assertNotIn("Expected values", compact.getvalue())
        self.assertNotIn("CHECK DETAILS", compact.getvalue())
        self.assertIn("CHECK DETAILS", detailed.getvalue())
        self.assertIn("kernel.dmesg_restrict", detailed.getvalue())

    def test_network_default_limits_inventory_and_details_expands_it(self):
        endpoints = tuple(
            ListeningEndpoint("tcp", "LISTEN", f"127.0.0.{index}", 1000 + index, "LOOPBACK", f"demo{index}", index)
            for index in range(1, 11)
        )
        snapshot = NetworkSnapshot(endpoints, "test fixture", True)
        firewall_snapshot = app.FirewallSnapshot(
            (
                app.FirewallObservation(
                    "nftables",
                    "CONFIGURED",
                    "test fixture",
                    "Test ruleset collected",
                    ("tables=1", "chains=1", "rules=1", "families=ip"),
                ),
            ),
            (),
        )
        interface_snapshot = NetworkInterfaceSnapshot(
            (
                NetworkInterface(
                    "test0",
                    "UP",
                    ("UP", "LOWER_UP"),
                    ("192.0.2.10/24",),
                ),
            ),
            "test fixture",
        )
        compact = io.StringIO()
        with (
            patch.object(app, "collect_network_snapshot", return_value=snapshot),
            patch.object(app, "collect_network_interfaces", return_value=interface_snapshot),
            patch.object(app, "collect_firewall_snapshot", return_value=firewall_snapshot),
            redirect_stdout(compact),
        ):
            app._dispatch_command("scan network")
        detailed = io.StringIO()
        with (
            patch.object(app, "collect_network_snapshot", return_value=snapshot),
            patch.object(app, "collect_network_interfaces", return_value=interface_snapshot),
            patch.object(app, "collect_firewall_snapshot", return_value=firewall_snapshot),
            redirect_stdout(detailed),
        ):
            app._dispatch_command("scan network --details")

        self.assertIn("NETWORK EXPOSURE", compact.getvalue())
        self.assertIn("NETWORK INTERFACES", compact.getvalue())
        self.assertIn("FIREWALL CONFIGURATION", compact.getvalue())
        self.assertIn("FIREWALL POLICY ANALYSIS", compact.getvalue())
        self.assertIn("Host facts not collected for this scan.", compact.getvalue())
        self.assertIn(
            "firewall input and forwarding policy analysis",
            compact.getvalue(),
        )
        self.assertIn("Assessment results:", compact.getvalue())
        self.assertNotIn("Input-policy observations:", compact.getvalue())
        self.assertIn(
            "Inbound firewall policy could not be assessed",
            compact.getvalue(),
        )
        self.assertIn(
            "FIREWALL-INPUT-UNASSESSED-001",
            detailed.getvalue(),
        )
        self.assertIn("test0", compact.getvalue())
        self.assertIn("additional socket(s) omitted", compact.getvalue())
        self.assertNotIn("demo10", compact.getvalue())
        self.assertIn("demo10", detailed.getvalue())
        self.assertIn("192.0.2.10/24", detailed.getvalue())
        self.assertIn("nftables", detailed.getvalue())
        self.assertIn("rules=1", detailed.getvalue())
        self.assertIn("not automatically a vulnerability", detailed.getvalue())

    def test_service_missing_systemctl_is_reported_without_crashing(self):
        output = io.StringIO()
        with patch.object(
            app,
            "collect_services",
            side_effect=FileNotFoundError("systemctl is not installed"),
        ), redirect_stdout(output):
            app._dispatch_command("scan service")

        report = output.getvalue()
        self.assertIn("SERVICES", report)
        self.assertIn("NOT_ASSESSED", report)
        self.assertIn("systemctl is not installed", report)
        self.assertIn("FINAL RESULT", report)

    def test_service_details_add_unit_file_metadata_checks(self):
        service = Service("demo.service", state="active", enabled=True, unit_file_state="enabled")
        metadata = ((UnitFileObservation("demo.service", "/etc/systemd/system/demo.service", 1000, 0o666, True, False),), ())
        compact = io.StringIO()
        with patch.object(app, "collect_services", return_value=(service,)), patch.object(app, "collect_service_unit_file_metadata", return_value=metadata) as inspect, redirect_stdout(compact):
            app._dispatch_command("scan service")
        inspect.assert_not_called()
        detailed = io.StringIO()
        with patch.object(app, "collect_services", return_value=(service,)), patch.object(app, "collect_service_unit_file_metadata", return_value=metadata), redirect_stdout(detailed):
            app._dispatch_command("scan service --details")

        self.assertNotIn("SYSTEMD UNIT FILES", compact.getvalue())
        self.assertIn("SYSTEMD UNIT FILES", detailed.getvalue())
        self.assertIn("ISSUES DETECTED", detailed.getvalue())
        self.assertIn("demo.service", detailed.getvalue())

    def test_unit_file_report_counts_and_shows_all_coverage_review_items(self):
        coverage_review = tuple(
            f"coverage issue {index}" for index in range(1, 6)
        )
        check = UnitFileCheck(
            "demo.service",
            "/usr/lib/systemd/system/demo.service",
            FindingStatus.REVIEW,
            "Symbolic link requires review",
            "Verify the link target.",
        )
        assessment = UnitFileAssessment((check,), (), coverage_review)

        section = app._unit_file_report_section(assessment, details=True)

        facts = dict(section.facts)
        self.assertEqual(facts["Review"], "6")

        review_items = tuple(
            item for item in section.items if item.startswith("REVIEW: ")
        )
        self.assertEqual(len(review_items), 5)
        for item in coverage_review:
            self.assertIn(f"REVIEW: {item}", review_items)

    def test_ssh_details_expand_host_key_metadata_without_reading_keys(self):
        config = SSHConfig("prohibit-password", True, False, True)
        keys = tuple(
            SSHHostKeyObservation(f"/etc/ssh/ssh_host_demo{index}_key", 0, 0o600, True, False)
            for index in range(1, 10)
        )
        rule_patches = (
            patch.object(ssh_area, "collect_ssh_config", return_value=config),
            patch.object(ssh_host_keys_area, "collect_ssh_host_key_metadata", return_value=keys),
            patch.object(ssh_area, "check_ssh_root_login", return_value=()),
            patch.object(ssh_area, "check_ssh_password_authentication", return_value=()),
            patch.object(ssh_area, "check_ssh_empty_passwords", return_value=()),
            patch.object(ssh_area, "check_ssh_public_key_authentication", return_value=()),
        )
        compact = io.StringIO()
        with rule_patches[0], rule_patches[1], rule_patches[2], rule_patches[3], rule_patches[4], rule_patches[5], redirect_stdout(compact):
            app._dispatch_command("scan ssh")
        detailed = io.StringIO()
        with rule_patches[0], rule_patches[1], rule_patches[2], rule_patches[3], rule_patches[4], rule_patches[5], redirect_stdout(detailed):
            app._dispatch_command("scan ssh --details")

        self.assertIn("SSH HOST-KEY METADATA", compact.getvalue())
        self.assertNotIn("ssh_host_demo9_key", compact.getvalue())
        self.assertIn("ssh_host_demo9_key", detailed.getvalue())
        self.assertIn("contents were not read", detailed.getvalue())

    def test_full_scan_host_failure_is_reported_instead_of_crashing_cli(self):
        output = io.StringIO()
        with patch.object(host_area, "collect_system_info", side_effect=OSError("host facts unavailable")), redirect_stdout(output):
            app._dispatch_command("scan")

        self.assertIn("SYSTEM", output.getvalue())
        self.assertIn("NOT_ASSESSED", output.getvalue())
        self.assertIn("could not be collected reliably", output.getvalue())
        self.assertIn("Host: Host facts unavailable.", output.getvalue())
        self.assertIn("FINAL RESULT", output.getvalue())

    def test_rootless_incomplete_scan_explicitly_recommends_elevation(self):
        compact = io.StringIO()
        with patch.object(hardening_area, "collect_sysctl_observations", return_value=()), \
             patch("vulpnix.context.execution.current_privilege_context", return_value=PrivilegeContext(1000, "ROOTLESS")), \
             redirect_stdout(compact):
            app._dispatch_command("scan hardening")

        self.assertIn("ROOTLESS (UID 1000)", compact.getvalue())
        self.assertIn("current privileges", compact.getvalue())
        self.assertIn("sudo vulpnix", compact.getvalue())


if __name__ == "__main__":
    unittest.main()
