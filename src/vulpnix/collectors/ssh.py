"""Read-only collection of effective SSH daemon options."""

import shutil
import subprocess

from vulpnix.models import SSHConfig
from vulpnix.parsers.ssh import parse_ssh_config


def collect_ssh_config() -> SSHConfig:
    """Read effective global SSH login options without validating host keys."""
    sshd = shutil.which("sshd", path="/usr/sbin:/usr/bin:/sbin:/bin")
    if sshd is None:
        raise FileNotFoundError("sshd is not installed")

    result = subprocess.run(
        [sshd, "-G"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
        shell=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    return parse_ssh_config(result.stdout)
