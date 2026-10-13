"""Tests for read-only Linux kernel hardening checks."""

from pathlib import Path
import tempfile
import unittest

from vulpnix.collectors.hardening import HARDENING_KEYS, collect_sysctl_observations
from vulpnix.findings import FindingStatus
from vulpnix.models import SysctlObservation
from vulpnix.rules.hardening import assess_kernel_hardening


_SAFE = {
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "1",
    "kernel.yama.ptrace_scope": "1",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
    "fs.suid_dumpable": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
}


class SysctlCollectorTests(unittest.TestCase):
    def test_reads_only_fixed_allowlist(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for key in HARDENING_KEYS:
                path = root.joinpath(*key.split("."))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(_SAFE[key], encoding="ascii")
            observations = collect_sysctl_observations(root)
        self.assertEqual(tuple(item.key for item in observations), HARDENING_KEYS)
        self.assertTrue(all(item.value == _SAFE[item.key] for item in observations))

    def test_missing_and_unreadable_parameters_are_not_guessed(self):
        with tempfile.TemporaryDirectory() as temp:
            observations = collect_sysctl_observations(temp)
        self.assertTrue(observations)
        self.assertTrue(all(item.value is None and item.error for item in observations))


class KernelHardeningRulesTests(unittest.TestCase):
    def test_expected_values_pass_without_findings(self):
        assessment = assess_kernel_hardening(tuple(SysctlObservation(key, value) for key, value in _SAFE.items()))
        self.assertTrue(all(check.status is FindingStatus.PASS for check in assessment.checks))
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.incomplete_checks, 0)

    def test_exposed_dmesg_and_kernel_pointers_are_verified_failures(self):
        values = dict(_SAFE)
        values["kernel.dmesg_restrict"] = "0"
        values["kernel.kptr_restrict"] = "0"
        assessment = assess_kernel_hardening(tuple(SysctlObservation(key, value) for key, value in values.items()))
        failures = [finding for finding in assessment.findings if finding.status is FindingStatus.FAIL]
        self.assertEqual(len(failures), 2)

    def test_role_dependent_settings_are_review_not_false_vulnerabilities(self):
        values = dict(_SAFE)
        values["net.ipv4.conf.all.send_redirects"] = "1"
        values["fs.suid_dumpable"] = "2"
        assessment = assess_kernel_hardening(tuple(SysctlObservation(key, value) for key, value in values.items()))
        statuses = {check.key: check.status for check in assessment.checks}
        self.assertEqual(statuses["net.ipv4.conf.all.send_redirects"], FindingStatus.REVIEW)
        self.assertEqual(statuses["fs.suid_dumpable"], FindingStatus.REVIEW)
        self.assertFalse(any(finding.status is FindingStatus.FAIL for finding in assessment.findings))

    def test_missing_required_data_is_not_assessed_not_pass(self):
        observations = tuple(
            SysctlObservation(key, None, "permission denied") if key == "kernel.dmesg_restrict" else SysctlObservation(key, value)
            for key, value in _SAFE.items()
        )
        assessment = assess_kernel_hardening(observations)
        check = next(item for item in assessment.checks if item.key == "kernel.dmesg_restrict")
        self.assertEqual(check.status, FindingStatus.NOT_ASSESSED)
        self.assertGreater(assessment.incomplete_checks, 0)
