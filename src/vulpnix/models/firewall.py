"""Normalized, read-only firewall observations."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FirewallRule:
    """Selected control-flow information extracted from one firewall rule."""

    position: int
    target: str | None
    unconditional: bool
    target_chain: str | None = None
    conditions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FirewallChain:
    """Policy and ordered rule metadata for one firewall chain."""

    implementation: str
    family: str
    table: str
    name: str
    hook: str | None
    policy: str | None
    rules: tuple[FirewallRule, ...] = ()
    chain_type: str | None = None


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
    chains: tuple[FirewallChain, ...] = ()


@dataclass(frozen=True, slots=True)
class FirewallSnapshot:
    """Firewall observations plus collection-coverage limitations."""

    observations: tuple[FirewallObservation, ...]
    review: tuple[str, ...] = ()
