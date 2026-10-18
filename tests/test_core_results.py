import unittest

from vulpnix.core import AreaResult, AreaStatus, Fact, Finding, FindingStatus, Gap, Record


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


class RecordAndGapTests(unittest.TestCase):
    def test_record_fields_are_looked_up_by_name_with_a_default(self):
        record = Record("account", "alice", "alice", (("uid", 1000), ("groups", ("users",)), ("shell", None)))
        self.assertEqual(record.get("uid"), 1000)
        self.assertEqual(record.get("groups"), ("users",))
        self.assertIsNone(record.get("shell"))
        self.assertEqual(record.get("missing", "n/a"), "n/a")

    def test_gaps_can_name_their_subject_and_shared_cause(self):
        gap = Gap("sudo:alice", "alice: permission denied", subject="alice", cause="permission denied")
        self.assertEqual((gap.subject, gap.cause), ("alice", "permission denied"))
        self.assertIsNone(Gap("k", "message").subject)

    def test_results_carry_records_and_list_valued_facts(self):
        result = AreaResult(
            "x", "X", AreaStatus.COMPLETE,
            facts=(Fact("names", "Names", "a, b", raw=("a", "b")),),
            records=(Record("account", "a", "a"),),
        )
        self.assertEqual(result.facts[0].raw, ("a", "b"))
        self.assertEqual(result.records[0].kind, "account")


if __name__ == "__main__":
    unittest.main()
