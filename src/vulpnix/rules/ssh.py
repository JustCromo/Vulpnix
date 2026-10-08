"""SSH configuration review rules."""

from vulpnix.findings import Finding
from vulpnix.models import SSHConfig


def check_ssh_root_login(config: SSHConfig) -> tuple[Finding, ...]:
    """Report when the global SSH option permits root login."""
    if config.permit_root_login != "yes":
        return ()

    return (
        Finding(
            rule_id="SSH-ROOT-LOGIN-001",
            title="Direct SSH root login is permitted",
            evidence="Global PermitRootLogin: yes",
            explanation=(
                "The global sshd option permits root login. Match rules and other "
                "access controls may change the effective result for a connection."
            ),
            recommendation=(
                "Review whether direct root access is needed; if not, disable it "
                "and use named accounts with privilege escalation."
            ),
        ),
    )


def check_ssh_empty_passwords(config: SSHConfig) -> tuple[Finding, ...]:
    """Report when password authentication accepts empty passwords."""
    if not (config.password_authentication and config.permit_empty_passwords):
        return ()

    return (
        Finding(
            rule_id="SSH-EMPTY-PASSWORD-001",
            title="SSH permits empty passwords",
            evidence=(
                "Global PasswordAuthentication: yes; "
                "PermitEmptyPasswords: yes"
            ),
            explanation=(
                "The global sshd options allow password authentication with an "
                "empty password. Match rules and other access controls may change "
                "the effective result for a connection."
            ),
            recommendation=(
                "Set PermitEmptyPasswords to no unless empty-password logins are "
                "explicitly required."
            ),
        ),
    )
