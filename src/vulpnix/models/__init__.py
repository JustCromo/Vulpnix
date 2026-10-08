"""Structured data models used by Vulpnix."""

from vulpnix.models.host import SystemInfo
from vulpnix.models.service import Service
from vulpnix.models.ssh import SSHConfig

__all__ = ["Service", "SSHConfig", "SystemInfo"]
