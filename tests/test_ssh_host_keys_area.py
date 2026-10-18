import unittest

from vulpnix.areas.ssh import SSHHostKeyArea
from vulpnix.cli.legacy_bridge import area_result_to_scan_result
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaStatus, FindingStatus
from vulpnix.models import SSHHostKeyObservation as Obs
from vulpnix.scan.privilege import PrivilegeContext

CTX = ExecutionContext(PrivilegeContext(0, "PRIVILEGED"), Environment.NATIVE)
GOOD = Obs("/etc/ssh/ssh_host_ed25519_key", 0, 0o600, True, False)


def run(*observations):
    return SSHHostKeyArea(lambda: tuple(observations)).run(CTX)


class SSHHostKeyAreaTests(unittest.TestCase):
    def test_safe_keys_are_complete_with_passing_facts_and_scope_notes(self):
        result = run(GOOD, Obs("/etc/ssh/ssh_host_rsa_key", 0, 0o400, True, False))
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.gaps, ())
        self.assertTrue(all(fact.status is FindingStatus.PASS for fact in result.facts))
        self.assertEqual(result.facts[0].value, "root-owned regular file, mode 0600")
        self.assertEqual(result.facts[0].label, GOOD.path)
        notes = " ".join(result.notes)
        self.assertIn("never read", notes)
        self.assertIn("HostKey", notes)

    def test_unsafe_key_is_a_failed_fact_and_a_fail_finding(self):
        bad = Obs("/etc/ssh/ssh_host_rsa_key", 1000, 0o640, True, False)
        result = run(GOOD, bad)
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual([f.status for f in result.facts], [FindingStatus.PASS, FindingStatus.FAIL])
        self.assertEqual([f.status for f in result.findings], [FindingStatus.FAIL])
        self.assertEqual(result.facts[1].value, "owner UID 1000 regular file, mode 0640")

    def test_symlink_is_review_and_never_a_failure(self):
        link = Obs("/etc/ssh/ssh_host_rsa_key", 0, 0o777, False, True)
        result = run(link)
        self.assertEqual(result.facts[0].status, FindingStatus.REVIEW)
        self.assertEqual(result.facts[0].value, "symbolic link; target not inspected")
        self.assertEqual([f.status for f in result.findings], [FindingStatus.REVIEW])

    def test_missing_directory_is_not_assessed_without_a_finding(self):
        result = run(Obs("/etc/ssh", None, None, None, False, "SSH configuration directory is not present"))
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.facts, ())
        self.assertIn("/etc/ssh", result.gaps[0].message)
        self.assertIn("not present", result.gaps[0].message)

    def test_one_unreadable_key_makes_the_area_partial_but_keeps_the_rest(self):
        result = run(GOOD, Obs("/etc/ssh/ssh_host_rsa_key", None, None, None, False, "permission denied"))
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertEqual(len(result.facts), 1)
        self.assertEqual(len(result.gaps), 1)
        self.assertEqual(result.findings, ())
        self.assertIn("permission denied", result.gaps[0].message)

    def test_missing_owner_or_mode_is_a_gap_not_a_failure(self):
        result = run(GOOD, Obs("/etc/ssh/ssh_host_rsa_key", None, 0o600, True, False))
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertFalse(any(f.status is FindingStatus.FAIL for f in result.findings))

    def test_no_observations_at_all_is_not_assessed(self):
        result = run()
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertEqual(result.facts, ())


class HostKeyLegacyViewTests(unittest.TestCase):
    def _section(self, result, details):
        legacy = area_result_to_scan_result(
            result, privilege=CTX.privilege, scope=("SSH host-key metadata",), details=details
        )
        return legacy, legacy.sections[0]

    def test_compact_view_keeps_counts_and_limits_the_attention_list(self):
        keys = [Obs(f"/etc/ssh/ssh_host_k{i}_key", 1000, 0o644, True, False) for i in range(8)]
        legacy, section = self._section(run(GOOD, *keys), details=False)
        facts = dict(section.facts)
        self.assertEqual(facts["Keys/observations"], "9")
        self.assertEqual(facts["Metadata checks passed"], "1")
        self.assertEqual(facts["Verified issues"], "8")
        self.assertEqual(facts["Unavailable/error"], "0")
        self.assertEqual(len(section.items), 7)
        self.assertIn("2 additional item(s) omitted", section.items[-1])
        self.assertIs(legacy.coverage, AssessmentCoverage.COMPLETE)
        self.assertEqual(legacy.review_items, 0)

    def test_details_list_every_key_and_say_contents_were_not_read(self):
        _, section = self._section(run(GOOD), details=True)
        self.assertEqual(len(section.items), 1)
        self.assertIn(GOOD.path, section.items[0])
        self.assertIn("contents were not read", section.items[0])

    def test_unassessed_area_is_partial_and_counts_one_review_item(self):
        result = run(Obs("/etc/ssh", None, None, None, False, "SSH configuration directory is not present"))
        legacy, section = self._section(result, details=False)
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)
        self.assertEqual(legacy.review_items, 1)
        self.assertEqual(section.status, "NOT_ASSESSED")
        self.assertEqual(legacy.findings, ())

    def test_partial_area_counts_gaps_as_unavailable(self):
        result = run(GOOD, Obs("/etc/ssh/ssh_host_rsa_key", None, None, None, False, "permission denied"))
        legacy, section = self._section(result, details=False)
        facts = dict(section.facts)
        self.assertEqual(facts["Keys/observations"], "2")
        self.assertEqual(facts["Unavailable/error"], "1")
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)
        self.assertEqual(legacy.review_items, 1)


if __name__ == "__main__":
    unittest.main()
