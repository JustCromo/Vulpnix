"""Tests for width-aware assessment report presentation."""

import io
import re
import unittest
from dataclasses import replace
from contextlib import redirect_stdout
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix_test_support import patch_supplementary_collectors
from vulpnix.cli.report import ReportSection, ScanReport, render_scan_report
from vulpnix.cli.terminal import display_width
from vulpnix.findings import Finding, FindingStatus
from vulpnix.risk import assess_findings
from vulpnix.models import SSHConfig, Service, SystemInfo, ListeningEndpoint, NetworkSnapshot
from vulpnix.scan.privilege import PrivilegeContext


def sample_report() -> ScanReport:
    return ScanReport(
        host=SystemInfo(
            hostname="vulpnix-host",
            distribution="Example Linux",
            distribution_version="3.2",
            kernel_release="6.8.1-generic",
            architecture="x86_64",
            uptime_seconds=3900,
        ),
        sections=(
            ReportSection(
                title="SERVICES",
                facts=(("Units", "12"), ("State", "4 active · 8 inactive · 0 other/unknown")),
                items=("example.service",),
            ),
            ReportSection(
                title="SSH",
                table=(
                    ("Root login", "key login only"),
                    ("Password authentication", "yes"),
                ),
                message="Values are global sshd options; Match rules may vary by connection.",
            ),
        ),
        findings=(
            Finding(
                rule_id="SSH-PASSWORD-AUTH-001",
                title="SSH password authentication is enabled",
                evidence="Global PasswordAuthentication: yes",
                explanation=(
                    "Password-based SSH login is enabled globally. Its risk depends on "
                    "the host's access controls, password policy, and exposure."
                ),
                recommendation=(
                    "Review whether password login is required; consider key-based "
                    "authentication and additional access controls."
                ),
            ),
        ),
        scope=("system facts", "services", "SSH configuration"),
    )


class ScanReportLayoutTests(unittest.TestCase):
    def render(self, width: int) -> list[str]:
        capture = io.StringIO()
        with redirect_stdout(capture):
            return render_scan_report(sample_report(), width)

    def test_80_column_report_uses_single_column_and_keeps_details(self) -> None:
        lines = self.render(80)
        self.assertTrue(all(display_width(line) <= 80 for line in lines))
        self.assertIn("OVERVIEW", lines)
        self.assertFalse(any("┌─ ASSESSMENT" in line for line in lines))
        self.assertIn("SSH password authentication is enabled", "\n".join(lines))
        self.assertIn("Global PasswordAuthentication: yes", "\n".join(lines))
        self.assertIn("key-based", "\n".join(lines))

    def test_120_column_report_keeps_sections_sequential(self) -> None:
        lines = self.render(120)
        self.assertTrue(all(display_width(line) <= 120 for line in lines))
        self.assertFalse(any("│" in line for line in lines))
        content = "\n".join(lines)
        details = content[content.index("DETAILS"):]
        self.assertLess(details.index("SYSTEM"), details.index("SERVICES"))
        self.assertLess(details.index("SERVICES"), details.index("SSH"))

    def test_narrow_report_wraps_without_losing_long_text(self) -> None:
        lines = self.render(36)
        joined = re.sub(r"\s+", " ", "\n".join(lines))
        self.assertTrue(all(display_width(line) <= 36 for line in lines))
        self.assertIn("Global PasswordAuthentication: yes", joined)
        self.assertIn("additional access controls", joined)

    def test_very_narrow_report_wraps_headings_and_labels(self) -> None:
        lines = self.render(20)
        self.assertTrue(all(display_width(line) <= 20 for line in lines))
        normalized = re.sub(r"\s+", " ", "\n".join(lines))
        self.assertIn("LINUX HOST ASSESSMENT", normalized)
        self.assertIn("SSH password authentication is enabled", normalized)

    def test_missing_severity_and_risk_are_not_invented(self) -> None:
        lines = self.render(80)
        joined = "\n".join(lines)
        self.assertNotIn("Severity", joined)
        self.assertNotIn("Risk score", joined)
        self.assertIn("[REVIEW]", joined)
        self.assertIn("SSH-PASSWORD-AUTH-001", joined)

    def test_attention_is_compact_and_rule_details_are_not_repeated(self) -> None:
        lines = self.render(80)
        attention_start = lines.index("ATTENTION · 1")
        details_start = lines.index("FINDING DETAILS")
        attention = lines[attention_start:details_start]
        joined = "\n".join(lines)
        self.assertTrue(any("⚠ REVIEW · SSH password authentication is enabled" in line for line in attention))
        self.assertFalse(any("Rule:" in line for line in attention))
        self.assertEqual(joined.count("SSH-PASSWORD-AUTH-001"), 1)
        self.assertIn("Global PasswordAuthentication: yes", joined)
        self.assertIn("Why it matters:", joined)
        self.assertIn("Recommendation:", joined)



class RiskAssessmentReportTests(unittest.TestCase):
    def make_finding(self, rule_id, status):
        return Finding(
            rule_id=rule_id,
            title="Test security finding",
            evidence="Deterministic test evidence",
            explanation="Test explanation.",
            recommendation="Test recommendation.",
            status=status,
        )

    def make_report(self, finding):
        assessment = assess_findings((finding,))
        return replace(
            sample_report(),
            findings=(finding,),
            risk_assessment=assessment,
        )

    def test_documented_risk_profile_renders_score_and_rationale(self) -> None:
        finding = self.make_finding(
            "FS-SETID-WORLD-WRITE-001",
            FindingStatus.FAIL,
        )
        report = self.make_report(finding)

        outputs = {}
        for width in (120, 80, 56, 36, 20):
            lines = render_scan_report(report, width)
            self.assertTrue(
                all(display_width(line) <= width for line in lines),
                f"Report exceeded terminal width {width}",
            )
            outputs[width] = re.sub(r"\s+", " ", "\n".join(lines))

        joined = outputs[80]
        self.assertIn("RISK ASSESSMENT", joined)
        self.assertIn("FS-SETID-WORLD-WRITE-001", joined)
        self.assertIn("CRITICAL", joined)
        self.assertIn("Score: 5 × 5 = 25", joined)
        self.assertIn("Rationale:", joined)
        self.assertIn("not a statistical measurement", joined)

    def test_long_risk_rule_id_stays_together_in_table(self) -> None:
        rule_id = "KERNEL-HARDENING-KERNEL-KPTR-RESTRICT"
        finding = self.make_finding(rule_id, FindingStatus.FAIL)
        report = self.make_report(finding)
        lines = render_scan_report(report, 80)

        self.assertTrue(any(rule_id in line for line in lines))
        self.assertTrue(all(display_width(line) <= 80 for line in lines))

    def test_review_finding_is_not_given_a_risk_score(self) -> None:
        finding = self.make_finding(
            "SSH-PASSWORD-AUTH-001",
            FindingStatus.REVIEW,
        )
        report = self.make_report(finding)
        joined = "\n".join(render_scan_report(report, 80))

        self.assertIn("Scored findings: 0", joined)
        self.assertIn("No verified FAIL findings", joined)
        self.assertNotIn("Score: 5 × 5", joined)
        self.assertNotIn("Verified FAIL findings not scored", joined)

    def test_unprofiled_verified_finding_is_listed_without_score(self) -> None:
        finding = self.make_finding(
            "UNPROFILED-TEST-001",
            FindingStatus.FAIL,
        )
        report = self.make_report(finding)
        joined = "\n".join(render_scan_report(report, 80))

        self.assertIn("Verified FAIL findings not scored", joined)
        self.assertIn("UNPROFILED-TEST-001", joined)
        self.assertNotIn("Rationale: ", joined)



class FullScanWidthTests(unittest.TestCase):
    def run_scan(self, width: int) -> list[str]:
        output = io.StringIO()
        with (
            patch_supplementary_collectors(app),
            patch("vulpnix.scan.orchestrator.current_privilege_context", return_value=PrivilegeContext(1000, "ROOTLESS")),
            patch.object(app, "collect_network_snapshot", return_value=NetworkSnapshot((ListeningEndpoint("tcp", "LISTEN", "0.0.0.0", 22, "ALL INTERFACES", None, None),), "test fixture", False, ("process ownership may be incomplete without elevated privileges",))),
            patch.object(
                app,
                "collect_firewall_snapshot",
                return_value=app.FirewallSnapshot(
                    (
                        app.FirewallObservation(
                            "nftables", "EMPTY", "test fixture", "Fixture observation",
                            ("tables=0", "chains=0", "rules=0", "families=ip"),
                        ),
                    ),
                    (),
                ),
            ),
            patch.object(app, "terminal_size", return_value=(width, 40)),
            patch.object(app, "collect_system_info", return_value=sample_report().host),
            patch.object(app, "collect_local_users", return_value=()),
            patch.object(app, "collect_sudo_privileges", return_value=()),
            patch.object(app, "collect_sensitive_file_metadata", return_value=()),
            patch.object(
                app,
                "collect_services",
                return_value=tuple(
                    Service(
                        name=name,
                        state="active",
                        enabled=True,
                        unit_file_state="enabled",
                    )
                    for name in (
                        "bluetooth.service",
                        "libvirtd.service",
                        "ollama.service",
                        "sshd.service",
                        "systemd-timesyncd.service",
                    )
                ),
            ),
            patch.object(
                app,
                "collect_ssh_config",
                return_value=SSHConfig(
                    permit_root_login="prohibit-password",
                    password_authentication=True,
                    permit_empty_passwords=False,
                    public_key_authentication=True,
                ),
            ),
            redirect_stdout(output),
        ):
            app._show_scan(detailed=True)
        app._OUTPUT_LAYOUT_CACHE = None
        return app._fit_output_to_width(output.getvalue().splitlines(), width)

    def test_full_scan_layout_at_80_and_120_columns(self) -> None:
        narrow = self.run_scan(80)
        wide = self.run_scan(120)
        self.assertTrue(all(display_width(line) <= 80 for line in narrow))
        self.assertTrue(all(display_width(line) <= 120 for line in wide))
        self.assertFalse(any("│" in line for line in narrow + wide))
        normalized = re.sub(r"\s+", " ", "\n".join(narrow))
        normalized_wide = re.sub(r"\s+", " ", "\n".join(wide))
        for text in (
            "vulpnix-host",
            "Example Linux (3.2)",
            "6.8.1-generic",
            "x86_64",
            "1h 5m",
            "Root login",
            "Password authentication",
            "Public-key authentication",
            "Empty passwords",
            "Values are global sshd options",
            "Units 5",
            "5 active",
            "5 yes",
            "Active now and enabled to start at boot:",
            "bluetooth.service",
            "libvirtd.service",
            "ollama.service",
            "sshd.service",
            "systemd-timesyncd.service",
            "SSH-PASSWORD-AUTH-001",
            "Global PasswordAuthentication: yes",
            "Why it matters:",
            "Recommendation:",
            (
                "Password-based SSH login is enabled globally. Its risk depends on "
                "the host's access controls, password policy, and exposure. Match "
                "rules may change the effective result for a connection."
            ),
            (
                "Review whether password login is required; consider key-based "
                "authentication and any additional access controls in use."
            ),
            "RISK ASSESSMENT",
            "FINAL RESULT",
            "REVIEW REQUIRED",
            "Some checks could not be completed with the current privileges.",
            "Use elevated privileges to complete checks that need them: sudo vulpnix",
        ):
            self.assertIn(text, normalized)
            self.assertIn(text, normalized_wide)
        for service_name in (
            "bluetooth.service",
            "libvirtd.service",
            "ollama.service",
            "sshd.service",
            "systemd-timesyncd.service",
        ):
            self.assertTrue(any(service_name in line for line in narrow))
            self.assertTrue(any(service_name in line for line in wide))


if __name__ == "__main__":
    unittest.main()
