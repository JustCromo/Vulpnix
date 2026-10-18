import subprocess
import unittest

from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaResult, AreaStatus
from vulpnix.engine import Area, AreaRegistry, run_area
from vulpnix.scan.privilege import PrivilegeContext

CTX = ExecutionContext(PrivilegeContext(1000, "ROOTLESS"), Environment.NATIVE)


class FakeArea:
    def __init__(self, area_id="fake", behaviour=None):
        self.id = area_id
        self.title = area_id.upper()
        self.description = "fake area"
        self._behaviour = behaviour

    def run(self, ctx):
        if self._behaviour is not None:
            return self._behaviour()
        return AreaResult(self.id, self.title, AreaStatus.COMPLETE)


class RegistryTests(unittest.TestCase):
    def test_keeps_registration_order_and_looks_up_by_id(self):
        registry = AreaRegistry([FakeArea("b"), FakeArea("a")])
        self.assertEqual(registry.ids(), ("b", "a"))
        self.assertEqual(registry.get("a").id, "a")
        self.assertIn("b", registry)
        self.assertEqual(len(registry), 2)

    def test_rejects_duplicates_unknown_ids_and_non_areas(self):
        registry = AreaRegistry([FakeArea("a")])
        with self.assertRaises(ValueError):
            registry.register(FakeArea("a"))
        with self.assertRaises(KeyError):
            registry.get("missing")
        with self.assertRaises(TypeError):
            registry.register(object())

    def test_fake_area_satisfies_contract(self):
        self.assertIsInstance(FakeArea(), Area)


class RunnerTests(unittest.TestCase):
    def test_expected_failures_become_error_results(self):
        for error in (
            OSError("permission denied"),
            subprocess.TimeoutExpired("cmd", 5),
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"),
            ValueError("bad\x00data"),
        ):
            with self.subTest(error=type(error).__name__):
                def boom(error=error):
                    raise error
                result = run_area(FakeArea(behaviour=boom), CTX)
                self.assertIs(result.status, AreaStatus.ERROR)
                self.assertEqual(result.findings, ())
                self.assertTrue(result.gaps[0].message.startswith("FAKE could not be assessed"))
                self.assertTrue(result.gaps[0].message.isprintable())

    def test_programming_errors_are_not_hidden(self):
        def bug():
            raise KeyError("bug")
        with self.assertRaises(KeyError):
            run_area(FakeArea(behaviour=bug), CTX)

    def test_result_for_another_area_is_rejected(self):
        area = FakeArea("a", behaviour=lambda: AreaResult("b", "B", AreaStatus.COMPLETE))
        with self.assertRaises(ValueError):
            run_area(area, CTX)


if __name__ == "__main__":
    unittest.main()
