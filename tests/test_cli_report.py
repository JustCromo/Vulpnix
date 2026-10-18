"""Tests for width-aware assessment report presentation."""

import io
import re
import unittest
from dataclasses import replace
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from vulpnix.cli import app
from vulpnix.areas.filesystem import area as filesystem_area
from vulpnix.areas.services import area as services_area
from vulpnix.areas.users import area as users_area
from vulpnix.areas.host import area as host_area
from vulpnix.areas.ssh import area as ssh_area
from vulpnix_test_support import patch_supplementary_collectors
from vulpnix.cli.report import ReportSection, ScanReport, render_scan_report
from vulpnix.cli.terminal import accent, color, display_width
from vulpnix.findings import (
    CVEAssessment,
    CVSSScore,
    Finding,
    FindingStatus,
)
from vulpnix.risk import assess_findings
from vulpnix.risk.engine import assess_host_risk
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


    def test_compact_report_summarizes_findings_without_technical_dump(self) -> None:
        report = replace(sample_report(), details=False)
        lines = render_scan_report(report, 80)
        joined = "\n".join(lines)

        self.assertIn("ASSESSMENT SUMMARY", joined)
        self.assertIn("Coverage:", joined)
        self.assertIn("ATTENTION", joined)
        self.assertIn("REVIEW REQUIRED", joined)
        self.assertIn("SSH password authentication is enabled", joined)
        self.assertIn("AREA SUMMARY", joined)
        self.assertIn("FINAL RESULT", joined)
        self.assertNotIn("FINDING DETAILS", joined)
        self.assertNotIn("Why it matters:", joined)
        self.assertNotIn("Evidence:", joined)
        self.assertNotIn("Global PasswordAuthentication: yes", joined)

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

    def test_cve_cvss_metadata_is_shown_in_finding_details(self) -> None:
        finding = Finding(
            rule_id="PACKAGE-CVE-TEST",
            title="Example package has a vulnerability",
            evidence="Matched installed package version.",
            explanation="Controlled CVE/CVSS test.",
            recommendation="Update the affected package.",
            status=FindingStatus.FAIL,
            severity="HIGH",
            cves=(
                CVEAssessment(
                    cve_id="CVE-2025-12345",
                    cvss=(
                        CVSSScore(
                            version="3.1",
                            base_score=9.8,
                            severity="CRITICAL",
                            vector=(
                                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                                "S:U/C:H/I:H/A:H"
                            ),
                            source="OSV.dev",
                        ),
                    ),
                ),
                CVEAssessment(cve_id="CVE-2025-67890"),
            ),
        )
        report = replace(sample_report(), findings=(finding,))
        lines = render_scan_report(report, 80)
        joined = "\n".join(lines)
        normalized = re.sub(r"\\s+", " ", joined)

        self.assertIn("CVE-2025-12345", normalized)
        self.assertIn("CVSS 3.1: 9.8 · CRITICAL", normalized)
        self.assertIn("CVSS source: OSV.dev", normalized)
        self.assertIn("CVSS vector:", normalized)
        self.assertIn("CVE-2025-67890", normalized)
        self.assertIn("CVSS unavailable", normalized)
        self.assertTrue(all(display_width(line) <= 80 for line in lines))

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
            patch("vulpnix.context.execution.current_privilege_context", return_value=PrivilegeContext(1000, "ROOTLESS")),
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
            patch.object(host_area, "collect_system_info", return_value=sample_report().host),
            patch.object(users_area, "collect_local_users", return_value=()),
            patch.object(users_area, "collect_sudo_privileges", return_value=()),
            patch.object(filesystem_area, "collect_sensitive_file_metadata", return_value=()),
            patch.object(
                services_area,
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
                ssh_area,
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



    def test_final_result_names_verified_issue_and_recommendation(self) -> None:
        base = sample_report()
        finding = replace(
            base.findings[0],
            status=FindingStatus.FAIL,
            recommendation="Disable SSH password authentication unless required.",
        )
        report = replace(
            base,
            findings=(finding,),
            risk_assessment=assess_findings((finding,)),
            details=False,
        )

        rendered = "\n".join(render_scan_report(report, 80))
        self.assertIn("ISSUES DETECTED", rendered)
        self.assertIn("VERIFIED ISSUE(S) · 1", rendered)
        self.assertIn("SSH password authentication is enabled", rendered)
        self.assertIn("Recommended action:", rendered)
        self.assertIn(
            "Disable SSH password authentication unless required.",
            rendered,
        )

    def test_final_result_keeps_host_score_without_repeating_finding_risk(self) -> None:
        base = sample_report()
        finding = replace(
            base.findings[0],
            status=FindingStatus.FAIL,
            impact=3,
            probability=3,
            risk_rationale="Controlled test profile.",
        )
        report = replace(
            base,
            findings=(finding,),
            risk_assessment=assess_findings((finding,)),
            details=False,
        )

        rendered = "\\n".join(render_scan_report(report, 80))

        self.assertIn("Observed host risk score: 9/25", rendered)
        self.assertNotIn("Risk:", rendered)
        self.assertNotIn("MODERATE (9/25)", rendered)

    def test_each_cve_uses_its_own_cvss_severity_color(self) -> None:
        base = sample_report()
        severities = (
            ("CVE-2025-10001", "LOW", 2.9),
            ("CVE-2025-10002", "MEDIUM", 5.5),
            ("CVE-2025-10003", "HIGH", 8.1),
            ("CVE-2025-10004", "CRITICAL", 9.8),
        )
        cves = tuple(
            CVEAssessment(
                cve_id=cve_id,
                cvss=(
                    CVSSScore(
                        version="3.1",
                        base_score=score,
                        severity=severity,
                        vector=f"CVSS:3.1/test-{severity.lower()}",
                        source="Test fixture",
                    ),
                ),
            )
            for cve_id, severity, score in severities
        )
        finding = replace(base.findings[0], cves=cves)
        report = replace(base, findings=(finding,))

        fake_stdout = MagicMock()
        fake_stdout.isatty.return_value = True
        with patch("vulpnix.cli.terminal.sys.stdout", fake_stdout):
            rendered = "\\n".join(render_scan_report(report, 80))

        for cve_id, severity, score in severities:
            with self.subTest(cve=cve_id):
                self.assertIn(cve_id, rendered)
                self.assertIn(f"CVSS 3.1: {score:.1f} · {severity}", rendered)

        for color_code in (
            "38;2;134;239;172m",  # LOW: green
            "38;2;255;205;128m",  # MEDIUM: amber
            "38;2;255;151;97m",   # HIGH: orange
            "38;2;255;112;112m",  # CRITICAL: red
        ):
            self.assertIn(color_code, rendered)

    def test_report_uses_semantic_colors_on_interactive_terminal(self) -> None:
        base = sample_report()
        finding = replace(base.findings[0], status=FindingStatus.FAIL)
        report = replace(
            base,
            findings=(finding,),
            risk_assessment=assess_findings((finding,)),
            details=False,
        )
        fake_stdout = MagicMock()
        fake_stdout.isatty.return_value = True

        with patch("vulpnix.cli.terminal.sys.stdout", fake_stdout):
            rendered = "\n".join(render_scan_report(report, 80))

        self.assertIn("38;2;255;112;112m", rendered)
        self.assertIn("38;2;255;205;128m", rendered)

    def test_no_color_disables_styles_even_on_interactive_terminal(self) -> None:
        fake_stdout = MagicMock()
        fake_stdout.isatty.return_value = True

        with (
            patch.dict("os.environ", {"NO_COLOR": "1"}),
            patch("vulpnix.cli.terminal.sys.stdout", fake_stdout),
        ):
            self.assertEqual(color("status", (255, 112, 112), bold=True), "status")
            self.assertEqual(accent("brand", bold=True), "brand")


class HostRiskSummaryReportTests(unittest.TestCase):
    def test_observed_risk_score_is_present_when_no_verified_findings_exist(self):
        report = replace(
            sample_report(),
            findings=(),
            risk_assessment=assess_findings(()),
            details=False,
        )
        rendered = " ".join(render_scan_report(report, 80))
        self.assertIn("Observed host risk score: 0/25", rendered)
        self.assertIn("Coverage: COMPLETE", rendered)
        self.assertNotIn("Coverage qualifier:", rendered)
        self.assertIn("COMPLETE", rendered)

    def test_final_result_and_risk_score_form_one_group(self):
        for details in (False, True):
            with self.subTest(details=details):
                report = replace(sample_report(), details=details)
                raw_lines = render_scan_report(report, 80)
                lines = [
                    re.sub(r"\x1b\[[0-9;]*m", "", line)
                    for line in raw_lines
                ]
                final_index = next(
                    index for index, line in enumerate(lines)
                    if "FINAL RESULT" in line
                )
                score_index = next(
                    index for index, line in enumerate(lines)
                    if "HOST RISK SCORE · CURRENT SCAN SCOPE" in line
                )
                score_value_index = next(
                    index for index, line in enumerate(lines)
                    if "Observed host risk score:" in line
                )
                coverage_index = next(
                    index for index, line in enumerate(lines)
                    if "Coverage: LIMITED" in line
                )

                self.assertEqual(score_index, final_index + 2)
                self.assertEqual(score_value_index, score_index + 1)
                self.assertEqual(coverage_index, score_value_index + 1)

                rendered = "\\n".join(lines)
                self.assertNotIn("Coverage qualifier:", rendered)
                self.assertIn("REVIEW REQUIRED", rendered)


    def test_observed_risk_score_uses_maximum_not_sum(self):
        base = sample_report().findings[0]
        first = replace(
            base,
            rule_id="TEST-RISK-ONE",
            status=FindingStatus.FAIL,
            impact=3,
            probability=3,
            risk_rationale="test profile",
        )
        second = replace(
            base,
            rule_id="TEST-RISK-TWO",
            status=FindingStatus.FAIL,
            impact=4,
            probability=4,
            risk_rationale="test profile",
        )
        assessment = assess_findings((first, second))
        score = assess_host_risk(assessment)
        self.assertEqual(score.score, 16)

        report = replace(
            sample_report(),
            findings=(first, second),
            risk_assessment=assessment,
            details=False,
        )
        rendered = " ".join(render_scan_report(report, 80))
        self.assertIn("Observed host risk score: 16/25", rendered)
        self.assertNotIn("Observed host risk score: 25/25", rendered)



class ReportPlacementAndFactColorTests(unittest.TestCase):
    def test_host_risk_score_is_inside_final_result_in_both_layouts(self):
        base = sample_report()

        for details in (False, True):
            with self.subTest(details=details):
                report = replace(base, details=details)
                rendered = "\n".join(render_scan_report(report, 80))

                final_index = rendered.index("FINAL RESULT")
                score_index = rendered.index("HOST RISK SCORE")

                self.assertGreater(score_index, final_index)
                self.assertEqual(
                    rendered.count("HOST RISK SCORE · CURRENT SCAN SCOPE"),
                    1,
                )
                self.assertIn("Observed host risk score:", rendered)

    def test_section_titles_are_neutral_and_fact_values_are_styled(self):
        section = ReportSection(
            title="FILESYSTEM",
            facts=(
                ("Checks passing", "3"),
                ("Verified concerns", "1"),
                ("Review", "2"),
            ),
        )
        base = replace(
            sample_report(),
            sections=(section,),
            findings=(),
            risk_assessment=assess_findings(()),
        )

        green = "\x1b[38;2;134;239;172m"
        red = "\x1b[38;2;255;112;112m"
        amber = "\x1b[38;2;255;205;128m"

        for details in (False, True):
            with self.subTest(details=details):
                fake_stdout = MagicMock()
                fake_stdout.isatty.return_value = True
                report = replace(base, details=details)

                with patch("vulpnix.cli.terminal.sys.stdout", fake_stdout):
                    rendered = "\n".join(render_scan_report(report, 80))

                lines = rendered.splitlines()
                heading = next(
                    line for line in lines if line.strip() == "FILESYSTEM"
                )
                self.assertEqual(heading, "FILESYSTEM")

                passing_line = next(
                    line for line in lines if "Checks passing" in line
                )
                concern_line = next(
                    line for line in lines if "Verified concerns" in line
                )
                review_line = next(
                    line
                    for line in lines
                    if re.search(
                        r"\bReview(?::|\s{2,})",
                        re.sub(r"\x1b\[[0-9;]*m", "", line),
                    )
                )

                self.assertIn(green, passing_line)
                self.assertGreater(
                    passing_line.index(green),
                    passing_line.index("Checks passing") + len("Checks passing"),
                )

                self.assertIn(red, concern_line)
                self.assertGreater(
                    concern_line.index(red),
                    concern_line.index("Verified concerns")
                    + len("Verified concerns"),
                )

                self.assertIn(amber, review_line)
                self.assertGreater(
                    review_line.index(amber),
                    review_line.index("Review") + len("Review"),
                )

    def test_detailed_table_labels_remain_neutral(self):
        fake_stdout = MagicMock()
        fake_stdout.isatty.return_value = True

        with patch("vulpnix.cli.terminal.sys.stdout", fake_stdout):
            rendered = "\n".join(
                render_scan_report(replace(sample_report(), details=True), 80)
            )

        green = "\x1b[38;2;134;239;172m"
        amber = "\x1b[38;2;255;205;128m"
        root_line = next(
            line for line in rendered.splitlines()
            if "Root login" in line and "key login only" in line
        )
        password_line = next(
            line for line in rendered.splitlines()
            if "Password authentication" in line and "yes" in line
        )

        self.assertIn(green, root_line)
        self.assertGreater(
            root_line.index(green),
            root_line.index("Root login") + len("Root login"),
        )
        self.assertIn(amber, password_line)
        self.assertGreater(
            password_line.index(amber),
            password_line.index("Password authentication")
            + len("Password authentication"),
        )


if __name__ == "__main__":
    unittest.main()
