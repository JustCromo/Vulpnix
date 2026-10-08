"""Deterministic checks over collected host facts."""

from vulpnix.rules.ssh import check_ssh_empty_passwords, check_ssh_root_login

__all__ = ["check_ssh_empty_passwords", "check_ssh_root_login"]
