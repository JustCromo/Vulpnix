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
from vulpnix.models.service import Service
from vulpnix.models.ssh import SSHConfig, SSHConnectionContext
from vulpnix.models.sudo import SudoGrant, SudoPrivilege, SudoPrivilegeStatus
from vulpnix.models.user import User

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
]
