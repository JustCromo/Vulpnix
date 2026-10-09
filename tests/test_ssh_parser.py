import unittest

from vulpnix.parsers.ssh import parse_ssh_config


class ParseSSHConfigTests(unittest.TestCase):
    def test_parses_required_options_case_insensitively(self) -> None:
        config = parse_ssh_config(
            "\n".join(
                (
                    "PermitRootLogin prohibit-password",
                    "PasswordAuthentication yes",
                    "PermitEmptyPasswords no",
                    "PubkeyAuthentication no",
                )
            )
        )

        self.assertEqual(config.permit_root_login, "prohibit-password")
        self.assertTrue(config.password_authentication)
        self.assertFalse(config.permit_empty_passwords)
        self.assertFalse(config.public_key_authentication)

    def test_rejects_missing_public_key_option(self) -> None:
        output = (
            "permitrootlogin no\n"
            "passwordauthentication no\n"
            "permitemptypasswords no\n"
        )

        with self.assertRaisesRegex(ValueError, "PubkeyAuthentication"):
            parse_ssh_config(output)

    def test_rejects_invalid_public_key_value(self) -> None:
        output = (
            "permitrootlogin no\n"
            "passwordauthentication no\n"
            "permitemptypasswords no\n"
            "pubkeyauthentication maybe\n"
        )

        with self.assertRaisesRegex(ValueError, "PubkeyAuthentication"):
            parse_ssh_config(output)


if __name__ == "__main__":
    unittest.main()
