"""Observations collected once per scan and shared between areas.

Two areas that need the same data (the service list, the package inventory)
ask the context for it. The first request runs the collector; later requests
receive the same result, or the same failure. Consequences that matter for a
security tool:

* one consistent snapshot: sections cannot contradict each other because the
  host changed between two reads, and privileged commands run once;
* fail-closed: a failed collection is stored as a failure and re-raised for
  every later request. It is never turned into an empty result, so "could not
  look" can never become "found nothing";
* only failures caused by the observed system are stored; a bug in Vulpnix
  propagates immediately and is not hidden behind the cache;
* provenance: every observation records where it came from and when, so any
  piece of evidence can be traced to a command or file and a time;
* in memory only, for the lifetime of one scan; nothing is written to disk.

Values are raw observed data and are untrusted. Areas judge them; only the
sanitized ``AreaResult`` ever reaches a renderer.

The cache is not thread-safe: areas run one after another.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from vulpnix.core.errors import EXPECTED_FAILURES


@dataclass(frozen=True, slots=True)
class Observation:
    """The outcome of one collection: a value or the failure that prevented it."""

    key: str
    source: str
    observed_at: datetime
    value: object = None
    error: Exception | None = None

    @property
    def failed(self) -> bool:
        return self.error is not None

    def unwrap(self):
        """Return the value, or raise the original failure."""
        if self.error is not None:
            raise self.error
        return self.value


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ObservationCache:
    """Per-scan store of collected data, keyed by what was observed."""

    def __init__(self, clock: Callable[[], datetime] = _utc_now) -> None:
        self._clock = clock
        self._items: dict[str, Observation] = {}

    def get(self, key: str, collector: Callable[[], object], *, source: str | None = None):
        """Return the observation's value, collecting it on first request."""
        observation = self._items.get(key)
        if observation is None:
            observed_at = self._clock()
            try:
                observation = Observation(key, source or key, observed_at, value=collector())
            except EXPECTED_FAILURES as error:
                observation = Observation(key, source or key, observed_at, error=error)
            self._items[key] = observation
        return observation.unwrap()

    def peek(self, key: str) -> Observation | None:
        return self._items.get(key)

    def observations(self) -> tuple[Observation, ...]:
        """Everything observed so far, in the order it was collected."""
        return tuple(self._items.values())
