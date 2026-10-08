"""Parsers for effective sshd configuration output."""

from vulpnix.models import SSHConfig


def parse_ssh_config(output: str) -> SSHConfig:
    """Parse effective global SSH login options from sshd output."""
    options: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) == 2 and fields[0].lower() in {
            "permitrootlogin",
            "passwordauthentication",
            "permitemptypasswords",
        }:
            options[fields[0].lower()] = fields[1].strip().lower()

    root_login = options.get("permitrootlogin")
    password_auth = options.get("passwordauthentication")
    empty_passwords = options.get("permitemptypasswords")
    if root_login not in {"yes", "no", "prohibit-password", "forced-commands-only"}:
        raise ValueError("sshd did not return a valid PermitRootLogin value")
    if password_auth not in {"yes", "no"}:
        raise ValueError("sshd did not return a valid PasswordAuthentication value")
    if empty_passwords not in {"yes", "no"}:
        raise ValueError("sshd did not return a valid PermitEmptyPasswords value")

    return SSHConfig(
        permit_root_login=root_login,
        password_authentication=password_auth == "yes",
        permit_empty_passwords=empty_passwords == "yes",
    )
