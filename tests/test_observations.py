from datetime import datetime, timedelta, timezone
import subprocess
import unittest

from vulpnix.context import Environment, ExecutionContext, ObservationCache
from vulpnix.scan.privilege import PrivilegeContext


class Counter:
    def __init__(self, value=None, error=None):
        self.calls = 0
        self._value, self._error = value, error

    def __call__(self):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._value


class ObservationCacheTests(unittest.TestCase):
    def test_a_collector_runs_once_and_every_asker_gets_the_same_value(self):
        cache, collector = ObservationCache(), Counter(("a", "b"))
        first = cache.get("services", collector)
        second = cache.get("services", collector)
        self.assertEqual(collector.calls, 1)
        self.assertIs(first, second)

    def test_different_keys_are_collected_separately(self):
        cache = ObservationCache()
        a, b = Counter(1), Counter(2)
        self.assertEqual((cache.get("a", a), cache.get("b", b)), (1, 2))
        self.assertEqual((a.calls, b.calls), (1, 1))

    def test_a_failure_is_stored_and_reraised_never_turned_into_an_empty_result(self):
        for error in (
            FileNotFoundError("systemctl is not installed"),
            subprocess.TimeoutExpired("systemctl", 10),
            ValueError("unreadable"),
        ):
            with self.subTest(error=type(error).__name__):
                cache, collector = ObservationCache(), Counter(error=error)
                for _ in range(3):
                    with self.assertRaises(type(error)) as caught:
                        cache.get("services", collector)
                    self.assertIs(caught.exception, error)
                self.assertEqual(collector.calls, 1)
                self.assertTrue(cache.peek("services").failed)

    def test_programming_errors_are_not_cached_and_always_surface(self):
        cache, collector = ObservationCache(), Counter(error=KeyError("bug"))
        for _ in range(2):
            with self.assertRaises(KeyError):
                cache.get("services", collector)
        self.assertEqual(collector.calls, 2)
        self.assertIsNone(cache.peek("services"))

    def test_an_empty_result_is_a_value_not_a_failure(self):
        cache = ObservationCache()
        self.assertEqual(cache.get("services", Counter(())), ())
        self.assertFalse(cache.peek("services").failed)

    def test_provenance_records_source_and_time_in_collection_order(self):
        times = iter(datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc) + timedelta(seconds=n) for n in range(5))
        cache = ObservationCache(clock=lambda: next(times))
        cache.get("b", Counter(1), source="systemctl list-units")
        with self.assertRaises(OSError):
            cache.get("a", Counter(error=OSError("x")))
        observations = cache.observations()
        self.assertEqual([o.key for o in observations], ["b", "a"])
        self.assertEqual(observations[0].source, "systemctl list-units")
        self.assertEqual(observations[1].source, "a")  # defaults to the key
        self.assertLess(observations[0].observed_at, observations[1].observed_at)
        self.assertEqual(observations[0].observed_at.tzinfo, timezone.utc)

    def test_each_context_has_its_own_cache(self):
        make = lambda: ExecutionContext(PrivilegeContext(0, "PRIVILEGED"), Environment.NATIVE)
        one, two = make(), make()
        one.observations.get("k", Counter(1))
        self.assertIsNone(two.observations.peek("k"))


if __name__ == "__main__":
    unittest.main()
