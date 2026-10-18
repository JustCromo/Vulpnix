import unittest

from vulpnix.core import AreaResult, AreaStatus, Fact, Finding, FindingStatus, Gap


def _finding() -> Finding:
    return Finding("T-001", "title", "evidence", "explanation", "recommendation")


class AreaResultInvariantTests(unittest.TestCase):
    def test_complete_area_cannot_have_gaps(self):
        with self.assertRaises(ValueError):
            AreaResult("x", "X", AreaStatus.COMPLETE, gaps=(Gap("g", "not verified"),))

    def test_partial_area_must_say_what_was_not_verified(self):
        with self.assertRaises(ValueError):
            AreaResult("x", "X", AreaStatus.PARTIAL)

    def test_not_assessed_and_error_need_a_reason_and_no_findings(self):
        for status in (AreaStatus.NOT_ASSESSED, AreaStatus.ERROR):
            with self.subTest(status=status):
                with self.assertRaises(ValueError):
                    AreaResult("x", "X", status)
                with self.assertRaises(ValueError):
                    AreaResult("x", "X", status, findings=(_finding(),), gaps=(Gap("g", "why"),))

    def test_empty_area_id_is_rejected(self):
        with self.assertRaises(ValueError):
            AreaResult(" ", "X", AreaStatus.COMPLETE)

    def test_valid_results_keep_structured_data(self):
        fact = Fact("k", "Label", "value", FindingStatus.PASS)
        result = AreaResult("x", "X", AreaStatus.COMPLETE, facts=(fact,), notes=("scope",))
        self.assertEqual(result.facts[0].status, FindingStatus.PASS)
        partial = AreaResult("x", "X", AreaStatus.PARTIAL, gaps=(Gap("g", "not verified"),))
        self.assertEqual(partial.gaps[0].key, "g")


if __name__ == "__main__":
    unittest.main()
