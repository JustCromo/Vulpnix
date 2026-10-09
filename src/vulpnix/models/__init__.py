"""Structured data models used by Vulpnix."""

from vulpnix.models.host import SystemInfo
from vulpnix.models.service import Service
from vulpnix.models.ssh import SSHConfig, SSHConnectionContext
from vulpnix.models.user import User

__all__ = ["Service", "SSHConfig", "SSHConnectionContext", "SystemInfo", "User"]
