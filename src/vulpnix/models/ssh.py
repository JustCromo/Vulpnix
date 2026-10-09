"""SSH daemon configuration data model."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SSHConnectionContext:
    """Connection attributes used to evaluate sshd Match rules."""

    user: str
    host: str
    addr: str
    laddr: str
    lport: int

    def as_spec(self) -> str:
        """Format the context for sshd's -C command-line option."""
        return (
            f"user={self.user},host={self.host},addr={self.addr},"
            f"laddr={self.laddr},lport={self.lport}"
        )


@dataclass(frozen=True, slots=True)
class SSHConfig:
    """Effective global SSH daemon options relevant to remote login."""

    permit_root_login: str
    password_authentication: bool
    permit_empty_passwords: bool
    public_key_authentication: bool
    connection_context: SSHConnectionContext | None = None
