"""Normalized local listening-socket inventory."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ListeningEndpoint:
    protocol: str
    state: str
    address: str
    port: int | None
    bind_scope: str
    process_name: str | None = None
    pid: int | None = None

@dataclass(frozen=True, slots=True)
class NetworkInterface:
    name: str
    state: str
    flags: tuple[str, ...]
    addresses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    endpoints: tuple[ListeningEndpoint, ...]
    source: str
    process_attribution_complete: bool
    review: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class NetworkInterfaceSnapshot:
    interfaces: tuple[NetworkInterface, ...]
    source: str
    review: tuple[str, ...] = ()
