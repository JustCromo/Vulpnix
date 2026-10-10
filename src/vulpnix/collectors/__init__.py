"""Read-only host data collectors."""

from vulpnix.collectors.host import collect_system_info
from vulpnix.collectors.filesystem import collect_sensitive_file_metadata
from vulpnix.collectors.setid import collect_setid_files
from vulpnix.collectors.ssh import collect_ssh_config
from vulpnix.collectors.systemd import collect_services
from vulpnix.collectors.sudo import collect_sudo_privileges
from vulpnix.collectors.users import collect_local_users

__all__ = [
    "collect_local_users",
    "collect_sensitive_file_metadata",
    "collect_setid_files",
    "collect_services",
    "collect_ssh_config",
    "collect_sudo_privileges",
    "collect_system_info",
]
