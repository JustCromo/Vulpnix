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


def check_ssh_password_authentication(config: SSHConfig) -> tuple[Finding, ...]:
    """Flag password-based SSH login for administrator review."""
    if not config.password_authentication:
        return ()

    return (
        Finding(
            rule_id="SSH-PASSWORD-AUTH-001",
            title="SSH password authentication is enabled",
            evidence="Global PasswordAuthentication: yes",
            explanation=(
                "Password-based SSH login is enabled globally. Its risk depends "
                "on the host's access controls, password policy, and exposure. "
                "Match rules may change the effective result for a connection."
            ),
            recommendation=(
                "Review whether password login is required; consider key-based "
                "authentication and any additional access controls in use."
            ),
        ),
    )


def check_ssh_public_key_authentication(config: SSHConfig) -> tuple[Finding, ...]:
    """Flag disabled public-key SSH authentication for administrator review."""
    if config.public_key_authentication:
        return ()

    return (
        Finding(
            rule_id="SSH-PUBKEY-AUTH-001",
            title="SSH public-key authentication is disabled",
            evidence="Global PubkeyAuthentication: no",
            explanation=(
                "Public-key SSH authentication is disabled globally. This may be "
                "intentional, but it removes a commonly used login method. Match "
                "rules may change the effective result for a connection."
            ),
            recommendation=(
                "Confirm that this is intentional and that the remaining SSH "
                "authentication methods meet the host's access requirements."
            ),
        ),
    )
