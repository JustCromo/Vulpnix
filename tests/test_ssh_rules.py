import unittest

from vulpnix.models import SSHConfig
from vulpnix.rules import (
    check_ssh_empty_passwords,
    check_ssh_password_authentication,
    check_ssh_public_key_authentication,
    check_ssh_root_login,
)


def make_config(
    *,
    root_login: str = "no",
    password_auth: bool = False,
    empty_passwords: bool = False,
    public_key_auth: bool = True,
) -> SSHConfig:
    return SSHConfig(
        permit_root_login=root_login,
        password_authentication=password_auth,
        permit_empty_passwords=empty_passwords,
        public_key_authentication=public_key_auth,
    )


class SSHRuleTests(unittest.TestCase):
    def test_root_login_rule_only_reports_permitted_root_login(self) -> None:
        self.assertEqual(len(check_ssh_root_login(make_config(root_login="yes"))), 1)
        self.assertEqual(check_ssh_root_login(make_config()), ())

    def test_password_authentication_is_a_review_finding_when_enabled(self) -> None:
        findings = check_ssh_password_authentication(
            make_config(password_auth=True)
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SSH-PASSWORD-AUTH-001")
        self.assertEqual(check_ssh_password_authentication(make_config()), ())

    def test_empty_password_rule_requires_both_options(self) -> None:
        findings = check_ssh_empty_passwords(
            make_config(password_auth=True, empty_passwords=True)
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(check_ssh_empty_passwords(make_config()), ())
        self.assertEqual(
            check_ssh_empty_passwords(make_config(empty_passwords=True)), ()
        )

    def test_disabled_public_key_authentication_is_reported(self) -> None:
        findings = check_ssh_public_key_authentication(
            make_config(public_key_auth=False)
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "SSH-PUBKEY-AUTH-001")
        self.assertEqual(
            check_ssh_public_key_authentication(make_config()), ()
        )


if __name__ == "__main__":
    unittest.main()
