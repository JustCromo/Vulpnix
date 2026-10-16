"""Tests for Linux package inventory and distribution-aware CVE sources."""

import io
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vulpnix.collectors.packages import (
    _parse_package_lines,
    _manager_for,
    collect_package_inventory,
    read_os_release,
)
from vulpnix.collectors.package_audit import (
    _osv_ecosystem,
    _version_compare_arch,
    collect_package_audit,
)
from vulpnix.findings import FindingStatus
from vulpnix.models.packages import InstalledPackage, PackageInventory


class PackageInventoryTests(unittest.TestCase):
    def test_os_release_is_parsed_as_data(self):
        with patch("pathlib.Path.read_text", return_value='ID="debian"\nVERSION_ID="12.8"\nNAME="Debian GNU/Linux"\n'):
            data = read_os_release()
        self.assertEqual(data["ID"], "debian")
        self.assertEqual(data["VERSION_ID"], "12.8")
        self.assertEqual(data["NAME"], "Debian GNU/Linux")

    def test_known_distribution_selects_its_own_package_manager(self):
        self.assertEqual(
            _manager_for("arch", "", {"pacman": "/usr/bin/pacman", "dpkg-query": "/usr/bin/dpkg-query"}),
            "pacman",
        )

    def test_unknown_distribution_does_not_guess_between_multiple_managers(self):
        self.assertIsNone(
            _manager_for("some-linux", "", {"pacman": "/usr/bin/pacman", "rpm": "/usr/bin/rpm"})
        )

    def test_pacman_inventory_parser(self):
        packages, malformed = _parse_package_lines(
            "pacman", "bash 5.2.037-1\nopenssl 3.4.1-1\ninvalid-line\n"
        )
        self.assertEqual(len(packages), 2)
        self.assertEqual(packages[0].name, "bash")
        self.assertEqual(packages[0].version, "5.2.037-1")
        self.assertEqual(malformed, 1)

    def test_dpkg_inventory_parser_keeps_architecture(self):
        packages, malformed = _parse_package_lines(
            "dpkg-query", "openssl\t3.0.14-1\tamd64\n"
        )
        self.assertEqual(packages[0].name, "openssl")
        self.assertEqual(packages[0].architecture, "amd64")
        self.assertEqual(malformed, 0)

    def test_apk_parser_handles_hyphens_in_package_names_and_versions(self):
        packages, malformed = _parse_package_lines(
            "apk", "alpine-baselayout-3.6.5-r0\nbusybox-1.37.0-r1\n"
        )
        self.assertEqual(
            [(item.name, item.version) for item in packages],
            [("alpine-baselayout", "3.6.5-r0"), ("busybox", "1.37.0-r1")],
        )
        self.assertEqual(malformed, 0)

    def test_inventory_uses_detected_pacman_without_modifying_system(self):
        def fake_which(name):
            return f"/usr/bin/{name}" if name == "pacman" else None

        def fake_run(command, **kwargs):
            self.assertIn("-Q", command)
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["timeout"], 60)
            return SimpleNamespace(returncode=0, stdout="bash 5.2.037-1\n", stderr="")

        with patch("vulpnix.collectors.packages.read_os_release", return_value={
            "ID": "arch", "NAME": "Arch Linux", "VERSION_ID": "rolling"
        }):
            inventory = collect_package_inventory(which=fake_which, runner=fake_run)

        self.assertEqual(inventory.status, "OK")
        self.assertEqual(inventory.manager, "pacman")
        self.assertEqual(len(inventory.packages), 1)
        self.assertEqual(inventory.packages[0].name, "bash")

    def test_missing_selected_manager_is_not_assessed(self):
        with patch("vulpnix.collectors.packages.read_os_release", return_value={
            "ID": "debian", "NAME": "Debian", "VERSION_ID": "12"
        }):
            inventory = collect_package_inventory(which=lambda _: None)
        self.assertEqual(inventory.status, "NOT_ASSESSED")
        self.assertEqual(inventory.manager, "dpkg-query")


class PackageAuditTests(unittest.TestCase):
    def inventory(self, distro="arch", release="rolling", packages=None):
        return PackageInventory(
            distribution_id=distro,
            distribution_name=distro,
            release=release,
            manager="pacman",
            packages=tuple(packages or (InstalledPackage("demo", "1.0-1"),)),
            status="OK",
        )

    def test_osv_mapping_only_uses_configured_ecosystems(self):
        self.assertEqual(_osv_ecosystem(self.inventory("debian", "12.8")), "Debian:12")
        self.assertEqual(_osv_ecosystem(self.inventory("ubuntu", "24.04")), "Ubuntu:24.04")
        self.assertEqual(_osv_ecosystem(self.inventory("alpine", "3.22.1")), "Alpine:v3.22")
        self.assertIsNone(_osv_ecosystem(self.inventory("fedora", "43")))

    def test_arch_version_compare_requires_native_vercmp(self):
        self.assertIsNone(_version_compare_arch("1.0", "1.1", which=lambda _: None))

    def test_arch_tracker_confirmed_vulnerable_match_creates_fail_finding(self):
        feed = [{
            "name": "AVG-1234",
            "packages": ["demo"],
            "status": "Vulnerable",
            "severity": "High",
            "type": "arbitrary code execution",
            "fixed": "1.1-1",
            "issues": ["CVE-2025-12345"],
        }]

        def fake_which(name):
            return "/usr/bin/vercmp" if name == "vercmp" else None

        def fake_run(command, **kwargs):
            self.assertEqual(command[0], "/usr/bin/vercmp")
            return SimpleNamespace(returncode=0, stdout="-1", stderr="")

        inventory = self.inventory()
        with patch(
            "vulpnix.collectors.package_audit._http_json",
            return_value=feed,
        ):
            from vulpnix.collectors.package_audit import _arch_tracker_audit
            audit = _arch_tracker_audit(inventory, which=fake_which, runner=fake_run)

        self.assertEqual(audit.status, "OK")
        self.assertEqual(len(audit.findings), 1)
        self.assertEqual(audit.findings[0].status, FindingStatus.FAIL)
        self.assertIn("CVE-2025-12345", audit.findings[0].title)
        self.assertEqual(audit.findings[0].impact, 4)
        self.assertEqual(audit.findings[0].probability, 3)

    def test_arch_fixed_package_is_not_reported_vulnerable(self):
        feed = [{
            "name": "AVG-1234", "packages": ["demo"], "status": "Vulnerable",
            "severity": "High", "fixed": "1.0-1", "issues": ["CVE-2025-12345"],
        }]

        def fake_which(name):
            return "/usr/bin/vercmp" if name == "vercmp" else None

        def fake_run(command, **kwargs):
            return SimpleNamespace(returncode=0, stdout="0", stderr="")

        with patch("vulpnix.collectors.package_audit._http_json", return_value=feed):
            from vulpnix.collectors.package_audit import _arch_tracker_audit
            audit = _arch_tracker_audit(self.inventory(), which=fake_which, runner=fake_run)

        self.assertEqual(audit.findings, ())

    def test_unknown_arch_advisory_state_is_review_not_fail(self):
        feed = [{
            "name": "AVG-1234", "packages": ["demo"], "status": "Unknown",
            "severity": "High", "fixed": "1.1-1", "issues": ["CVE-2025-12345"],
        }]

        def fake_which(name):
            return "/usr/bin/vercmp" if name == "vercmp" else None

        def fake_run(command, **kwargs):
            return SimpleNamespace(returncode=0, stdout="-1", stderr="")

        with patch("vulpnix.collectors.package_audit._http_json", return_value=feed):
            from vulpnix.collectors.package_audit import _arch_tracker_audit
            audit = _arch_tracker_audit(self.inventory(), which=fake_which, runner=fake_run)

        self.assertEqual(audit.findings[0].status, FindingStatus.REVIEW)
        self.assertIsNone(audit.findings[0].impact)

    def test_unsupported_distribution_does_not_make_network_request(self):
        inventory = self.inventory("fedora", "43")
        with patch("vulpnix.collectors.package_audit._http_json") as fetch:
            audit = collect_package_audit(inventory)
        fetch.assert_not_called()
        self.assertEqual(audit.status, "NOT_ASSESSED")
        self.assertIn("No validated CVE ecosystem", audit.messages[0])

    def test_osv_exact_version_match_becomes_finding(self):
        inventory = self.inventory("debian", "12")
        responses = [
            {"results": [{"vulns": [{"id": "CVE-2025-12345"}]}]},
            {
                "id": "CVE-2025-12345",
                "summary": "Demo package issue",
                "aliases": [],
                "database_specific": {"severity": "HIGH"},
                "affected": [{
                    "package": {"name": "demo", "ecosystem": "Debian:12"},
                    "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2-1"}]}],
                }],
                "references": [{"type": "ADVISORY", "url": "https://example.invalid/advisory"}],
            },
        ]

        def fetcher(url, payload=None, **kwargs):
            return responses.pop(0)

        from vulpnix.collectors.package_audit import _osv_audit
        audit = _osv_audit(inventory, "Debian:12", fetcher=fetcher)

        self.assertEqual(audit.status, "OK")
        self.assertEqual(len(audit.findings), 1)
        self.assertEqual(audit.findings[0].status, FindingStatus.FAIL)
        self.assertEqual(audit.findings[0].severity, "HIGH")
        self.assertEqual(audit.findings[0].impact, 4)
        self.assertIn("1.2-1", audit.findings[0].recommendation)


    def test_osv_cve_keeps_calculated_cvss_separate_from_advisory_severity(self):
        responses = [
            {"results": [{"vulns": [{"id": "GHSA-demo"}]}]},
            {
                "id": "GHSA-demo",
                "summary": "Demo package issue",
                "aliases": ["CVE-2025-12345"],
                "database_specific": {"severity": "HIGH"},
                "severity": [{
                    "type": "CVSS_V3",
                    "score": (
                        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                        "S:U/C:H/I:H/A:H"
                    ),
                }],
                "affected": [{
                    "package": {"name": "demo", "ecosystem": "Debian:12"},
                    "ranges": [{"events": [
                        {"introduced": "0"},
                        {"fixed": "1.2-1"},
                    ]}],
                }],
                "references": [{
                    "type": "ADVISORY",
                    "url": "https://example.invalid/advisory",
                }],
            },
        ]

        def fetcher(url, payload=None, **kwargs):
            return responses.pop(0)

        from vulpnix.collectors.package_audit import _osv_audit

        audit = _osv_audit(
            self.inventory("debian", "12"),
            "Debian:12",
            fetcher=fetcher,
        )

        self.assertEqual(len(audit.findings), 1)
        finding = audit.findings[0]

        # Source label and calculated CVSS are deliberately separate.
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(len(finding.cves), 1)
        self.assertEqual(finding.cves[0].cve_id, "CVE-2025-12345")
        self.assertEqual(len(finding.cves[0].cvss), 1)

        assessment = finding.cves[0].cvss[0]
        self.assertEqual(assessment.version, "3.1")
        self.assertEqual(assessment.base_score, 9.8)
        self.assertEqual(assessment.severity, "CRITICAL")
        self.assertEqual(assessment.source, "OSV.dev")
        self.assertTrue(assessment.vector.startswith("CVSS:3.1/"))

if __name__ == "__main__":
    unittest.main()
