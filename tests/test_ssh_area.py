import subprocess
import unittest

from vulpnix.areas.ssh import SSHConfigArea
from vulpnix.cli.legacy_bridge import area_result_to_scan_result
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.collectors.ssh import SSHCommandError, SSHGUnsupportedError
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaStatus, FindingStatus
from vulpnix.models import SSHConfig
from vulpnix.scan.privilege import PrivilegeContext

CTX = ExecutionContext(PrivilegeContext(0, "PRIVILEGED"), Environment.NATIVE)


def run(config=None, error=None):
    def collector():
        if error is not None:
            raise error
        return config
    return SSHConfigArea(collector).run(CTX)


class SSHAreaTests(unittest.TestCase):
    def test_hardened_configuration_passes_every_checked_value(self):
        result = run(SSHConfig("no", False, False, True))
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual(result.findings, ())
        self.assertEqual(
            [(fact.key, fact.value, fact.status) for fact in result.facts],
            [
                ("root_login", "no", FindingStatus.PASS),
                ("password_authentication", "no", FindingStatus.PASS),
                ("public_key_authentication", "yes", FindingStatus.PASS),
                ("empty_passwords", "no", FindingStatus.PASS),
            ],
        )
        self.assertIn("Match rules", result.notes[0])

    def test_fact_judgments_always_match_the_rule_findings(self):
        result = run(SSHConfig("yes", True, True, False))
        statuses = {fact.key: fact.status for fact in result.facts}
        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertEqual(
            rule_ids,
            {"SSH-ROOT-LOGIN-001", "SSH-PASSWORD-AUTH-001",
             "SSH-EMPTY-PASSWORD-001", "SSH-PUBKEY-AUTH-001"},
        )
        # The rules report REVIEW; the facts must say the same, never more.
        self.assertTrue(all(status is FindingStatus.REVIEW for status in statuses.values()))

    def test_empty_passwords_without_password_login_is_not_flagged(self):
        result = run(SSHConfig("no", False, True, True))
        empty = next(fact for fact in result.facts if fact.key == "empty_passwords")
        self.assertEqual(empty.value, "yes")
        self.assertIs(empty.status, FindingStatus.PASS)
        self.assertEqual(result.findings, ())

    def test_key_only_root_login_is_labelled_for_people(self):
        result = run(SSHConfig("prohibit-password", False, False, True))
        self.assertEqual(result.facts[0].value, "key login only")

    def test_unavailable_sshd_is_not_assessed_with_a_reason(self):
        cases = {
            FileNotFoundError("sshd is not installed"): "not installed",
            subprocess.TimeoutExpired("sshd", 5): "in time",
            SSHGUnsupportedError(255, "", "unknown option -- G", option="-G"): "not supported",
            SSHCommandError(1, "", "bad\x07config", option="-T"): "-T failed",
        }
        for error, expected in cases.items():
            with self.subTest(error=type(error).__name__):
                result = run(error=error)
                self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
                self.assertEqual(result.findings, ())
                self.assertIn(expected, result.gaps[0].message)
                self.assertTrue(result.gaps[0].message.isprintable())


class LegacyBridgeTests(unittest.TestCase):
    def test_review_findings_do_not_reduce_collection_coverage(self):
        area = run(SSHConfig("no", True, False, True))
        legacy = area_result_to_scan_result(area, privilege=CTX.privilege, scope=("SSH configuration",))
        self.assertIs(legacy.coverage, AssessmentCoverage.COMPLETE)
        self.assertEqual(legacy.review_items, 0)
        self.assertEqual(len(legacy.findings), 1)
        section = legacy.sections[0]
        self.assertEqual(section.table[1], ("Password authentication", "yes"))
        self.assertIn("Match rules", section.footer)

    def test_not_assessed_area_is_partial_with_one_review_item(self):
        area = run(error=FileNotFoundError("sshd is not installed"))
        legacy = area_result_to_scan_result(area, privilege=CTX.privilege, scope=("SSH configuration",))
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)
        self.assertEqual(legacy.review_items, 1)
        self.assertEqual(legacy.sections[0].status, "NOT_ASSESSED")
        self.assertIn("not installed", legacy.sections[0].message)


if __name__ == "__main__":
    unittest.main()
