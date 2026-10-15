"""Tests for presentation-level assessment summaries."""

import unittest

from vulpnix.cli.summary import (
    AssessmentCoverage,
    AssessmentResult,
    build_assessment_summary,
)
from vulpnix.findings import Finding, FindingStatus


def make_finding(status: FindingStatus) -> Finding:
    return Finding(
        rule_id="TEST-001",
        title="Controlled test finding",
        evidence="Controlled test evidence",
        explanation="Controlled test explanation",
        recommendation="Controlled test recommendation",
        status=status,
    )


class AssessmentSummaryTests(unittest.TestCase):
    def test_partial_coverage_avoids_redundant_conclusion(self):
        summary = build_assessment_summary(
            findings=(),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=264,
        )

        self.assertEqual(summary.result, AssessmentResult.REVIEW_REQUIRED)
        self.assertIn(
            "No verified security issues were identified by the completed checks.",
            summary.description,
        )
        self.assertEqual(
            summary.action,
            "Review incomplete checks to determine whether further assessment is needed.",
        )

        combined = f"{summary.description} {summary.action}"
        self.assertNotIn(
            "No verified vulnerability requires immediate remediation",
            combined,
        )
        self.assertEqual(summary.review_items, 264)

    def test_complete_coverage_with_review_findings_requires_review(self):
        summary = build_assessment_summary(
            findings=(make_finding(FindingStatus.REVIEW),),
            coverage=AssessmentCoverage.COMPLETE,
            review_items=0,
        )

        self.assertEqual(summary.result, AssessmentResult.REVIEW_REQUIRED)
        self.assertIn("items need review", summary.description)
        self.assertEqual(
            summary.action,
            "Review flagged items to determine whether further assessment is needed.",
        )
        self.assertEqual(summary.review_items, 1)

    def test_complete_clean_assessment_keeps_existing_result(self):
        summary = build_assessment_summary(
            findings=(),
            coverage=AssessmentCoverage.COMPLETE,
            review_items=0,
        )

        self.assertEqual(summary.result, AssessmentResult.NO_VERIFIED_ISSUES)
        self.assertEqual(
            summary.description,
            "No verified security issues were detected.",
        )
        self.assertEqual(
            summary.action,
            "No immediate remediation is required.",
        )


if __name__ == "__main__":
    unittest.main()
