"""Models for installed software and package vulnerability assessments."""

from dataclasses import dataclass

from vulpnix.findings import Finding


@dataclass(frozen=True, slots=True)
class InstalledPackage:
    name: str
    version: str
    architecture: str | None = None
    source_name: str | None = None
    source_version: str | None = None


@dataclass(frozen=True, slots=True)
class PackageInventory:
    distribution_id: str
    distribution_name: str
    release: str
    manager: str
    packages: tuple[InstalledPackage, ...]
    status: str
    messages: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PackageAudit:
    source: str
    status: str
    packages_checked: int
    findings: tuple[Finding, ...] = ()
    messages: tuple[str, ...] = ()
