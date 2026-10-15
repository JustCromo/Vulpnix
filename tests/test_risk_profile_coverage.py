"""Coverage gates for default risk profiles used by verified findings."""

import unittest

from vulpnix.findings import Finding, FindingStatus
from vulpnix.risk.engine import RiskLevel, assess_findings
from vulpnix.risk.profiles import DEFAULT_PROFILES
from vulpnix.rules.hardening import _RULES as HARDENING_RULES


REQUIRED_VERIFIED_FAIL_RULES = frozenset({
    "FS-SENSITIVE-OWNER-001",
    "FS-SENSITIVE-WRITE-001",
    "FS-SECRET-WORLD-READ-001",
    "FS-SETID-WORLD-WRITE-001",
    "SYSTEMD-UNIT-METADATA-001",
    "SSH-HOST-KEY-METADATA-001",
})


def hardening_rule_id(rule):
    return (
        "KERNEL-HARDENING-"
        + rule.key.upper().replace(".", "-").replace("_", "-")
    )


class RiskProfileCoverageTests(unittest.TestCase):

    def test_every_current_verified_fail_rule_has_a_default_profile(self):
        expected = set(REQUIRED_VERIFIED_FAIL_RULES)
        expected.update(
            hardening_rule_id(rule)
            for rule in HARDENING_RULES
            if rule.fail_values
        )

        missing = sorted(expected - set(DEFAULT_PROFILES))
        self.assertEqual(
            missing,
            [],
            f"Verified-FAIL rules without profiles: {missing}",
        )

    def test_every_default_profile_has_valid_factors_and_rationale(self):
        self.assertTrue(DEFAULT_PROFILES)

        for rule_id, profile in DEFAULT_PROFILES.items():
            with self.subTest(rule_id=rule_id):
                self.assertIsInstance(profile.impact, int)
                self.assertNotIsInstance(profile.impact, bool)
                self.assertIn(profile.impact, range(1, 6))

                self.assertIsInstance(profile.probability, int)
                self.assertNotIsInstance(profile.probability, bool)
                self.assertIn(profile.probability, range(1, 6))

                self.assertIsInstance(profile.rationale, str)
                self.assertTrue(profile.rationale.strip())

    def test_unsafe_ssh_host_key_metadata_uses_default_profile(self):
        finding = Finding(
            rule_id="SSH-HOST-KEY-METADATA-001",
            title="SSH host private-key metadata is unsafe",
            evidence=(
                "/etc/ssh/ssh_host_ed25519_key: "
                "mode 0644 allows group/other access"
            ),
            explanation="Host private-key material should be restricted.",
            recommendation="Restrict key ownership and permissions.",
            status=FindingStatus.FAIL,
        )

        assessment = assess_findings((finding,))

        self.assertEqual(len(assessment.scored), 1)
        self.assertEqual(assessment.unscored_verified, ())

        risk = assessment.scored[0]
        self.assertEqual(risk.impact, 5)
        self.assertEqual(risk.probability, 3)
        self.assertEqual(risk.score, 15)
        self.assertEqual(risk.level, RiskLevel.HIGH)
        self.assertTrue(risk.rationale.strip())


if __name__ == "__main__":
    unittest.main()
