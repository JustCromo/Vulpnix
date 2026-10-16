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
    _nvd_cvss_for_cves,
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

    def test_xbps_parser_keeps_hyphenated_names_and_ignores_unconfigured_packages(self):
        packages, malformed = _parse_package_lines(
            "xbps-query",
            "ii bash-5.2.37_1 GNU Bash\n"
            "ii libfoo-32bit-1.2_1 Example library\n"
            "uu partial-1.0_1 Needs configuration\n",
        )
        self.assertEqual(
            [(item.name, item.version) for item in packages],
            [("bash", "5.2.37_1"), ("libfoo-32bit", "1.2_1")],
        )
        self.assertEqual(malformed, 0)

    def test_dpkg_inventory_parser_keeps_source_metadata_and_architecture(self):
        packages, malformed = _parse_package_lines(
            "dpkg-query",
            "libfoo1\t1.2.3-1ubuntu1\tamd64\tfoo\t1.2.3-1\n",
        )
        self.assertEqual(packages[0].name, "libfoo1")
        self.assertEqual(packages[0].version, "1.2.3-1ubuntu1")
        self.assertEqual(packages[0].architecture, "amd64")
        self.assertEqual(packages[0].source_name, "foo")
        self.assertEqual(packages[0].source_version, "1.2.3-1")
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

    def test_void_uses_xbps_query_for_read_only_inventory(self):
        def fake_which(name):
            return "/usr/bin/xbps-query" if name == "xbps-query" else None

        def fake_run(command, **kwargs):
            self.assertEqual(command, ["/usr/bin/xbps-query", "-l"])
            self.assertFalse(kwargs["shell"])
            return SimpleNamespace(
                returncode=0,
                stdout=(
                    "ii bash-5.2.37_1 GNU Bash\n"
                    "ii openssl-3.4.1_1 TLS library\n"
                ),
                stderr="",
            )

        with patch(
            "vulpnix.collectors.packages.read_os_release",
            return_value={
                "ID": "void",
                "NAME": "Void Linux",
                "PRETTY_NAME": "Void Linux",
            },
        ):
            inventory = collect_package_inventory(
                which=fake_which,
                runner=fake_run,
            )

        self.assertEqual(inventory.status, "OK")
        self.assertEqual(inventory.manager, "xbps-query")
        self.assertEqual(len(inventory.packages), 2)
        self.assertEqual(inventory.packages[1].name, "openssl")

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
        self.assertEqual(_osv_ecosystem(self.inventory("ubuntu", "24.04")), "Ubuntu:24.04:LTS")
        self.assertEqual(_osv_ecosystem(self.inventory("alpine", "3.22.1")), "Alpine:v3.22")
        self.assertIsNone(_osv_ecosystem(self.inventory("fedora", "43")))

    def test_osv_mapping_covers_additional_supported_release_families(self):
        self.assertEqual(
            _osv_ecosystem(self.inventory("azurelinux", "3.0")),
            "Azure Linux:3.0",
        )
        self.assertEqual(
            _osv_ecosystem(self.inventory("cbl-mariner", "2.0")),
            "Azure Linux:2.0",
        )
        self.assertEqual(
            _osv_ecosystem(self.inventory("mageia", "9.1")),
            "Mageia:9",
        )
        self.assertEqual(
            _osv_ecosystem(self.inventory("ubuntu", "24.10")),
            "Ubuntu:24.10",
        )

        opensuse = PackageInventory(
            "opensuse-leap",
            "openSUSE Leap 15.6",
            "15.6",
            "rpm",
            (InstalledPackage("demo", "1.0-1"),),
            "OK",
        )
        self.assertEqual(
            _osv_ecosystem(opensuse),
            "openSUSE:openSUSE Leap 15.6",
        )

        suse = PackageInventory(
            "sles",
            "SUSE Linux Enterprise Server 15 SP6",
            "15.6",
            "rpm",
            (InstalledPackage("demo", "1.0-1"),),
            "OK",
        )
        self.assertEqual(
            _osv_ecosystem(suse),
            "SUSE:SUSE Linux Enterprise Server 15 SP6",
        )

        # Never invent a product-stream CPE for a generic RHEL install.
        self.assertIsNone(_osv_ecosystem(self.inventory("rhel", "9")))

    def test_nvd_duplicate_vectors_merge_sources_without_losing_distinct_scores(self):
        cve_id = "CVE-2099-54321"
        same_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        distinct_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H"

        response = {
            "vulnerabilities": [{
                "cve": {
                    "id": cve_id,
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "cve@vendor.example",
                                "cvssData": {"vectorString": same_vector},
                            },
                            {
                                "source": "nvd@nist.gov",
                                "cvssData": {"vectorString": same_vector},
                            },
                            {
                                "source": "nvd@nist.gov",
                                "cvssData": {"vectorString": distinct_vector},
                            },
                        ],
                    },
                },
            }],
        }

        with patch("vulpnix.collectors.package_audit._NVD_CVSS_CACHE", {}):
            scores_by_cve, messages = _nvd_cvss_for_cves(
                (cve_id,),
                fetcher=lambda _: response,
                sleeper=lambda _: None,
            )

        scores = scores_by_cve[cve_id]
        self.assertEqual(messages, ())
        self.assertEqual(len(scores), 2)

        same_score = next(score for score in scores if score.vector == same_vector)
        self.assertIn("cve@vendor.example", same_score.source)
        self.assertIn("nvd@nist.gov", same_score.source)
        self.assertEqual(
            same_score.source,
            "NVD (cve@vendor.example; nvd@nist.gov)",
        )
        self.assertTrue(any(score.vector == distinct_vector for score in scores))

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

    def test_osv_ubuntu_query_uses_source_package_metadata(self):
        from vulpnix.collectors.package_audit import _osv_audit

        inventory = self.inventory(
            "ubuntu",
            "24.04",
            packages=(
                InstalledPackage(
                    name="libfoo1",
                    version="1.2.3-1ubuntu1",
                    architecture="amd64",
                    source_name="foo",
                    source_version="1.2.3-1",
                ),
            ),
        )
        calls = []

        def fetcher(url, payload=None, **kwargs):
            calls.append((url, payload))
            return {"results": [{"vulns": []}]}

        audit = _osv_audit(
            inventory,
            "Ubuntu:24.04:LTS",
            fetcher=fetcher,
        )

        self.assertEqual(audit.status, "OK")
        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0][1],
            {
                "queries": [
                    {
                        "package": {
                            "name": "foo",
                            "ecosystem": "Ubuntu:24.04:LTS",
                        },
                        "version": "1.2.3-1",
                    }
                ]
            },
        )

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
