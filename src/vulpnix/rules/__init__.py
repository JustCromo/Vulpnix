"""Deterministic checks over collected host facts."""

from vulpnix.rules.ssh import (
    check_ssh_empty_passwords,
    check_ssh_password_authentication,
    check_ssh_public_key_authentication,
    check_ssh_root_login,
)
from vulpnix.rules.users import verified_privileged_accounts
from vulpnix.rules.filesystem import assess_sensitive_files

__all__ = [
    "check_ssh_empty_passwords",
    "check_ssh_password_authentication",
    "check_ssh_public_key_authentication",
    "check_ssh_root_login",
    "assess_sensitive_files",
    "verified_privileged_accounts",
]
