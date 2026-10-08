"""SSH daemon configuration data model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SSHConfig:
    """Effective global SSH daemon options relevant to remote login."""

    permit_root_login: str
    password_authentication: bool
