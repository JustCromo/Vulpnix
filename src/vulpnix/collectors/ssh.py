"""Read-only collection of effective SSH daemon options."""

from dataclasses import replace
import re
import shutil
import subprocess

from vulpnix.models import SSHConfig, SSHConnectionContext
from vulpnix.parsers.ssh import parse_ssh_config


_UNSUPPORTED_OPTION_PATTERNS = (
    re.compile(
        r"\b(?:unknown|unrecognized|unsupported|invalid|illegal|not supported|not recognized)"
        r"\s+(?:command.line\s+)?(?:option|flag)\b[\s:=-]{0,40}['\"]?-?G\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:option|flag)\s+['\"]?-?G\b.{0,40}\b"
        r"(?:unknown|unrecognized|unsupported|invalid|illegal|not supported|not recognized)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"['\"]?-?G\b.{0,40}\b(?:unknown|unrecognized|unsupported|invalid|illegal)"
        r"\s+(?:option|flag)\b",
        re.IGNORECASE,
    ),
)


class SSHCommandError(subprocess.SubprocessError):
    """An sshd command failed, retaining its process diagnostics."""

    def __init__(
        self,
        returncode: int,
        stdout: str,
        stderr: str,
        *,
        option: str = "-G",
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.option = option
        self.diagnostic = stderr.strip() or stdout.strip()
        super().__init__(f"sshd {option} exited with status {returncode}")


class SSHGUnsupportedError(SSHCommandError):
    """The installed sshd rejected the -G command-line option."""


def _is_unsupported_g_option(stdout: str, stderr: str) -> bool:
    diagnostic = f"{stderr}\n{stdout}"
    return any(pattern.search(diagnostic) for pattern in _UNSUPPORTED_OPTION_PATTERNS)


def collect_ssh_config(
    connection: SSHConnectionContext | None = None,
) -> SSHConfig:
    """Collect effective SSH options using supported OpenSSH test modes."""
    sshd = shutil.which("sshd", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if sshd is None:
        raise FileNotFoundError("sshd is not installed")

    def run_mode(option: str):
        command = [sshd, option]
        if connection is not None:
            command.extend(("-C", connection.as_spec()))

        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
            },
        )

    option = "-G"
    result = run_mode(option)

    # Older OpenSSH versions may not support -G. Fall back only when
    # diagnostics explicitly identify the option as unsupported.
    if result.returncode != 0 and _is_unsupported_g_option(
        result.stdout, result.stderr
    ):
        option = "-T"
        result = run_mode(option)

    if result.returncode != 0:
        raise SSHCommandError(
            result.returncode,
            result.stdout,
            result.stderr,
            option=option,
        )

    config = parse_ssh_config(result.stdout)
    if connection is not None:
        return replace(config, connection_context=connection)
    return config