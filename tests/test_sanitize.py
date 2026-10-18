import unittest

from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Fact, Finding, FindingStatus, Gap, Record
from vulpnix.core.sanitize import MAX_TEXT, clean, sanitize_result
from vulpnix.engine import run_area
from vulpnix.scan.privilege import PrivilegeContext

CTX = ExecutionContext(PrivilegeContext(0, "PRIVILEGED"), Environment.NATIVE)
EVIL = "x\x1b[2J\x1b]52;c;aGFjaw==\x07y\nFAIL: forged\r\ttab"


def hostile_result() -> AreaResult:
    finding = Finding(
        "T-1", "t" + EVIL, "e" + EVIL, "x" + EVIL, "r" + EVIL, FindingStatus.REVIEW,
        risk_rationale="why" + EVIL,
    )
    return AreaResult(
        "t", "T" + EVIL, AreaStatus.PARTIAL,
        findings=(finding,),
        facts=(Fact("k" + EVIL, "label" + EVIL, "value" + EVIL, FindingStatus.PASS, raw=("a" + EVIL, "b"), detail="d" + EVIL),),
        records=(Record("kind", "key" + EVIL, "label" + EVIL, (("field" + EVIL, "v" + EVIL), ("tuple", ("a" + EVIL,)), ("n", 5), ("none", None))),),
        gaps=(Gap("g" + EVIL, "m" + EVIL, subject="s" + EVIL, cause="c" + EVIL),),
        notes=("n" + EVIL,),
    )


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from strings(item)
    elif hasattr(value, "__dataclass_fields__"):
        for name in value.__dataclass_fields__:
            yield from strings(getattr(value, name))


class SanitizeTests(unittest.TestCase):
    def test_every_displayable_string_loses_its_control_characters(self):
        result = sanitize_result(hostile_result())
        found = list(strings(result))
        self.assertGreater(len(found), 20)
        for text in found:
            with self.subTest(text=text[:30]):
                self.assertTrue(text.isprintable(), repr(text))

    def test_replacement_keeps_the_rest_of_the_text(self):
        self.assertEqual(clean("a\x1b[2Jb"), "a\ufffd[2Jb")

    def test_non_text_values_are_left_alone(self):
        result = sanitize_result(hostile_result())
        fields = dict(result.records[0].fields)
        self.assertEqual((fields["n"], fields["none"]), (5, None))
        self.assertIs(result.facts[0].status, FindingStatus.PASS)
        self.assertIs(result.status, AreaStatus.PARTIAL)

    def test_very_long_strings_are_bounded(self):
        shown = clean("a" * 100_000)
        self.assertEqual(len(shown), MAX_TEXT)
        self.assertTrue(shown.endswith("…"))
        self.assertEqual(clean("a" * MAX_TEXT), "a" * MAX_TEXT)

    def test_invariants_still_hold_after_sanitizing(self):
        sanitize_result(hostile_result())  # AreaResult validates on every replace

    def test_run_area_sanitizes_whatever_an_area_returns(self):
        class Hostile:
            id, title, description = "t", "T", "hostile area"
            def run(self, ctx):
                return hostile_result()
        result = run_area(Hostile(), CTX)
        self.assertTrue(all(text.isprintable() for text in strings(result)))

    def test_error_results_are_printable_too(self):
        class Failing:
            id, title, description = "t", "T", "failing area"
            def run(self, ctx):
                raise OSError("boom" + EVIL)
        result = run_area(Failing(), CTX)
        self.assertIs(result.status, AreaStatus.ERROR)
        self.assertTrue(all(text.isprintable() for text in strings(result)))


if __name__ == "__main__":
    unittest.main()
