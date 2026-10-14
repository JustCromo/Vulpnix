"""Tests for evidence-gated, explainable risk scoring."""

import unittest

from vulpnix.findings import Finding, FindingStatus
from vulpnix.risk.engine import RiskLevel, assess_findings


def make_finding(
    rule_id: str,
    status: FindingStatus,
    impact: int | None = None,
    probability: int | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        evidence="Controlled test evidence",
        explanation="Controlled test explanation",
        recommendation="Controlled test recommendation",
        status=status,
        impact=impact,
        probability=probability,
        risk_rationale=(
            "Documented test rationale"
            if impact is not None and probability is not None
            else None
        ),
    )


class RiskEngineTests(unittest.TestCase):
    def test_scores_only_verified_fail_findings(self):
        findings = (
            make_finding("VERIFIED-001", FindingStatus.FAIL, 4, 5),
            make_finding("REVIEW-001", FindingStatus.REVIEW, 5, 5),
            make_finding("UNKNOWN-001", FindingStatus.NOT_ASSESSED, 5, 5),
            make_finding("ERROR-001", FindingStatus.ERROR, 5, 5),
            make_finding("PASS-001", FindingStatus.PASS, 5, 5),
        )

        assessment = assess_findings(findings)

        self.assertEqual(len(assessment.scored), 1)
        self.assertEqual(assessment.scored[0].rule_id, "VERIFIED-001")
        self.assertEqual(assessment.scored[0].impact, 4)
        self.assertEqual(assessment.scored[0].probability, 5)
        self.assertEqual(assessment.scored[0].score, 20)
        self.assertEqual(assessment.scored[0].level, RiskLevel.CRITICAL)
        self.assertEqual(assessment.unscored_verified, ())

    def test_verified_finding_without_factors_is_explicitly_unscored(self):
        finding = make_finding("NO-PROFILE-001", FindingStatus.FAIL)
        assessment = assess_findings((finding,))

        self.assertEqual(assessment.scored, ())
        self.assertEqual(assessment.unscored_verified, (finding,))

    def test_invalid_factor_values_are_not_scored(self):
        finding = make_finding("INVALID-001", FindingStatus.FAIL, 6, 2)
        assessment = assess_findings((finding,))

        self.assertEqual(assessment.scored, ())
        self.assertEqual(assessment.unscored_verified, (finding,))

    def test_risk_levels_follow_documented_score_bands(self):
        findings = (
            make_finding("LOW-001", FindingStatus.FAIL, 2, 2),
            make_finding("MODERATE-001", FindingStatus.FAIL, 3, 3),
            make_finding("HIGH-001", FindingStatus.FAIL, 4, 4),
            make_finding("CRITICAL-001", FindingStatus.FAIL, 4, 5),
        )

        assessment = assess_findings(findings)

        self.assertEqual(
            [(item.score, item.level) for item in assessment.scored],
            [
                (4, RiskLevel.LOW),
                (9, RiskLevel.MODERATE),
                (16, RiskLevel.HIGH),
                (20, RiskLevel.CRITICAL),
            ],
        )

    def test_missing_rationale_prevents_scoring(self):
        finding = Finding(
            rule_id="NO-RATIONALE-001",
            title="Finding without rationale",
            evidence="Evidence",
            explanation="Explanation",
            recommendation="Recommendation",
            status=FindingStatus.FAIL,
            impact=4,
            probability=3,
        )

        assessment = assess_findings((finding,))

        self.assertEqual(assessment.scored, ())
        self.assertEqual(assessment.unscored_verified, (finding,))


class RiskProfileIntegrationTests(unittest.TestCase):
    def test_verified_setid_finding_gets_documented_profile(self):
        finding = make_finding(
            "FS-SETID-WORLD-WRITE-001",
            FindingStatus.FAIL,
        )

        assessment = assess_findings((finding,))

        self.assertEqual(len(assessment.scored), 1)
        risk = assessment.scored[0]
        self.assertEqual(risk.impact, 5)
        self.assertEqual(risk.probability, 5)
        self.assertEqual(risk.score, risk.impact * risk.probability)
        self.assertEqual(risk.level, RiskLevel.CRITICAL)
        self.assertTrue(risk.rationale.strip())


if __name__ == "__main__":
    unittest.main()
