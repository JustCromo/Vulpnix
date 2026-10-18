"""SSH daemon configuration, expressed through the Area contract.

Collection, parsing and rules are unchanged (``collectors.ssh``,
``parsers.ssh``, ``rules.ssh``); this module only turns their output into an
``AreaResult``. Every fact's judgment comes from the rule that checks it, so a
value and its finding can never disagree.
"""

from __future__ import annotations

from collections.abc import Callable
import subprocess

from vulpnix.collectors.ssh import (
    SSHCommandError,
    SSHGUnsupportedError,
    collect_ssh_config,
)
from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Fact, Finding, FindingStatus, Gap
from vulpnix.models import SSHConfig
from vulpnix.rules.ssh import (
    check_ssh_empty_passwords,
    check_ssh_password_authentication,
    check_ssh_public_key_authentication,
    check_ssh_root_login,
)

SCOPE_NOTE = "Values are global sshd options; Match rules may vary by connection."

_ROOT_LOGIN_LABELS = {
    "yes": "yes",
    "no": "no",
    "prohibit-password": "key login only",
    "forced-commands-only": "restricted key login only",
}

# The errors collect_ssh_config can raise because of the observed system.
_SSH_UNAVAILABLE = (OSError, subprocess.SubprocessError, UnicodeError, ValueError)


def _printable(text: str) -> str:
    return "".join(ch if ch.isprintable() else "\N{REPLACEMENT CHARACTER}" for ch in text)


def _command_detail(error: SSHCommandError) -> str:
    if not error.diagnostic:
        return f" (exit {error.returncode})"
    return f" (exit {error.returncode}: {_printable(error.diagnostic)})"


def ssh_error_message(error: Exception) -> str:
    """Explain, in one sentence, why the SSH configuration is unavailable."""
    if isinstance(error, FileNotFoundError):
        return "OpenSSH server (sshd) is not installed."
    if isinstance(error, subprocess.TimeoutExpired):
        return "sshd did not return configuration in time."
    if isinstance(error, SSHGUnsupportedError):
        option = getattr(error, "option", "-G")
        return (
            f"sshd {option} is not supported by this OpenSSH installation."
            f"{_command_detail(error)}"
        )
    if isinstance(error, SSHCommandError):
        option = getattr(error, "option", "-G")
        return f"sshd {option} failed{_command_detail(error)}."
    if isinstance(error, subprocess.CalledProcessError):
        return "sshd -G could not print the effective configuration."
    if isinstance(error, (UnicodeError, ValueError)):
        return "sshd returned unreadable configuration data."
    return "SSH configuration is unavailable."


def _judged(findings: tuple[Finding, ...]) -> FindingStatus:
    """A checked value passes unless its rule produced a finding."""
    if not findings:
        return FindingStatus.PASS
    for status in (FindingStatus.FAIL, FindingStatus.ERROR, FindingStatus.NOT_ASSESSED):
        if any(finding.status is status for finding in findings):
            return status
    return FindingStatus.REVIEW


class SSHConfigArea:
    """Effective global sshd options relevant to remote login."""

    id = "ssh"
    title = "SSH"
    description = "SSH configuration and host-key metadata"

    def __init__(self, collector: Callable[[], SSHConfig] | None = None) -> None:
        # ``None`` resolves the collector at run time so tests can patch it.
        self._collector = collector

    def run(self, ctx: ExecutionContext) -> AreaResult:
        collector = self._collector or collect_ssh_config
        try:
            config = collector()
        except _SSH_UNAVAILABLE as error:
            return AreaResult(
                area_id=self.id,
                title=self.title,
                status=AreaStatus.NOT_ASSESSED,
                gaps=(Gap("sshd-config-unavailable", ssh_error_message(error)),),
            )

        root = check_ssh_root_login(config)
        password = check_ssh_password_authentication(config)
        pubkey = check_ssh_public_key_authentication(config)
        empty = check_ssh_empty_passwords(config)

        yes_no = {True: "yes", False: "no"}
        facts = (
            Fact(
                "root_login",
                "Root login",
                _ROOT_LOGIN_LABELS[config.permit_root_login],
                _judged(root),
            ),
            Fact(
                "password_authentication",
                "Password authentication",
                yes_no[config.password_authentication],
                _judged(password),
            ),
            Fact(
                "public_key_authentication",
                "Public-key authentication",
                yes_no[config.public_key_authentication],
                _judged(pubkey),
            ),
            Fact(
                "empty_passwords",
                "Empty passwords",
                yes_no[config.permit_empty_passwords],
                _judged(empty),
            ),
        )
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=AreaStatus.COMPLETE,
            # Same order as the previous CLI path.
            findings=(*root, *password, *empty, *pubkey),
            facts=facts,
            notes=(SCOPE_NOTE,),
        )
