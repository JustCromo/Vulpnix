"""Structured data models used by Vulpnix."""

from vulpnix.models.host import SystemInfo
from vulpnix.models.file_metadata import (
    FileMetadata,
    FileMetadataResult,
    FileMetadataStatus,
)
from vulpnix.models.filesystem_scan import (
    CoverageStatus,
    FilesystemCoverage,
    SetIdFile,
)
from vulpnix.models.network import (
    ListeningEndpoint,
    NetworkInterface,
    NetworkInterfaceSnapshot,
    NetworkSnapshot,
)
from vulpnix.models.firewall import FirewallChain, FirewallObservation, FirewallRule, FirewallSnapshot
from vulpnix.models.service import Service
from vulpnix.models.ssh import SSHConfig, SSHConnectionContext
from vulpnix.models.sudo import SudoGrant, SudoPrivilege, SudoPrivilegeStatus
from vulpnix.models.user import User
from vulpnix.models.hardening import SysctlObservation, HardeningCheck, HardeningAssessment
from vulpnix.models.ssh_keys import SSHHostKeyObservation, SSHHostKeyCheck, SSHHostKeyAssessment
from vulpnix.models.systemd_security import UnitFileObservation, UnitFileCheck, UnitFileAssessment

__all__ = [
    "Service",
    "FileMetadata",
    "FileMetadataResult",
    "FileMetadataStatus",
    "CoverageStatus",
    "FilesystemCoverage",
    "SetIdFile",
    "SSHConfig",
    "SSHConnectionContext",
    "SudoGrant",
    "SudoPrivilege",
    "SudoPrivilegeStatus",
    "SystemInfo",
    "User",
    "ListeningEndpoint",
    "NetworkSnapshot",
    "FirewallChain",
    "FirewallRule",
    "FirewallObservation",
    "FirewallSnapshot",
    "SysctlObservation",
    "HardeningCheck",
    "HardeningAssessment",
    "SSHHostKeyObservation",
    "SSHHostKeyCheck",
    "SSHHostKeyAssessment",
    "UnitFileObservation",
    "UnitFileCheck",
    "UnitFileAssessment",
    "NetworkInterface",
    "NetworkInterfaceSnapshot",
]
