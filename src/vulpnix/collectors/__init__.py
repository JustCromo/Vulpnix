"""Read-only host data collectors."""

from vulpnix.collectors.host import collect_system_info
from vulpnix.collectors.ssh import collect_ssh_config
from vulpnix.collectors.systemd import collect_services

__all__ = ["collect_services", "collect_ssh_config", "collect_system_info"]
