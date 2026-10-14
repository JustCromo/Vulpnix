"""Normalized, read-only firewall observations."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FirewallObservation:
    """Observation from one firewall implementation or ruleset interface.

    State is descriptive, not a verdict that the host is secure.
    Typical values include ACTIVE, INACTIVE, CONFIGURED, EMPTY,
    NOT_ASSESSED, and ERROR.
    """

    implementation: str
    state: str
    source: str
    summary: str
    details: tuple[str, ...] = ()
    review: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FirewallSnapshot:
    """Firewall observations plus collection-coverage limitations."""

    observations: tuple[FirewallObservation, ...]
    review: tuple[str, ...] = ()
