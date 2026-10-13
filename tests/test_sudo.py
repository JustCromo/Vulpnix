"""Deterministic tests for non-interactive sudo privilege inspection."""

import subprocess
import unittest
from unittest.mock import patch

from vulpnix.collectors.sudo import collect_sudo_privileges
from vulpnix.models import SudoPrivilegeStatus, User
from vulpnix.parsers.sudo import parse_sudo_listing
from vulpnix.rules.users import verified_privileged_accounts


class ParseSudoListingTests(unittest.TestCase):
    def test_parses_representative_grants_and_context(self) -> None:
        output = """Matching Defaults entries for alice on host-a:
    env_reset, secure_path=/usr/bin

User alice may run the following commands on host-a:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/id
    (root) PASSWD: /usr/bin/journalctl
"""
        result = parse_sudo_listing("alice", output)

        self.assertIs(result.status, SudoPrivilegeStatus.PRIVILEGES_FOUND)
        self.assertEqual(result.host, "host-a")
        self.assertEqual(len(result.grants), 2)
        self.assertEqual(result.grants[0].target_users, ("ALL",))
        self.assertEqual(result.grants[0].target_groups, ("ALL",))
        self.assertEqual(
            result.grants[0].allowed_commands,
            ("/usr/bin/systemctl", "/usr/bin/id"),
        )
        self.assertEqual(result.grants[0].options, ("NOPASSWD",))
        self.assertIsNone(result.grants[0].source)

    def test_accepts_common_header_variation_and_preserves_options(self) -> None:
        output = "User alice may run following commands on host-b:\n (root) SETENV: NOEXEC: ALL\n"
        result = parse_sudo_listing("alice", output)

        self.assertIs(result.status, SudoPrivilegeStatus.PRIVILEGES_FOUND)
        self.assertEqual(result.host, "host-b")
        self.assertEqual(result.grants[0].options, ("SETENV", "NOEXEC"))
        self.assertEqual(result.grants[0].allowed_commands, ("ALL",))

    def test_unambiguous_policy_denial_means_no_sudo_privileges(self) -> None:
        result = parse_sudo_listing(
            "alice",
            "",
            "Sorry, user alice may not run sudo on host-a.\n",
            returncode=1,
        )

        self.assertIs(result.status, SudoPrivilegeStatus.NO_PRIVILEGES)
        self.assertEqual(result.host, "host-a")

    def test_explicit_policy_denial_with_zero_exit_code_means_no_privileges(self) -> None:
        result = parse_sudo_listing(
            "bin",
            "",
            "User bin is not allowed to run sudo on archlinux.\n",
            returncode=0,
        )

        self.assertIs(result.status, SudoPrivilegeStatus.NO_PRIVILEGES)
        self.assertEqual(result.host, "archlinux")
        self.assertEqual(result.reason, "sudo explicitly reported no allowed commands")

    def test_password_required_is_not_assessed(self) -> None:
        result = parse_sudo_listing(
            "alice", "", "sudo: a password is required\n", returncode=1
        )

        self.assertIs(result.status, SudoPrivilegeStatus.NOT_ASSESSED)
        self.assertEqual(result.reason, "non-interactive listing requires authentication")

    def test_no_new_privileges_environment_block_is_not_assessed(self) -> None:
        result = parse_sudo_listing(
            "alice",
            "",
            'sudo: The "no new privileges" flag is set.\n',
            returncode=1,
        )

        self.assertIs(result.status, SudoPrivilegeStatus.NOT_ASSESSED)
        self.assertEqual(
            result.reason,
            "sudo execution blocked by environment or runtime configuration",
        )

    def test_permission_denied_inspecting_other_account_is_not_assessed(self) -> None:
        result = parse_sudo_listing(
            "bob",
            "",
            "sudo: user root is not allowed to list privileges for bob\n",
            returncode=1,
        )

        self.assertIs(result.status, SudoPrivilegeStatus.NOT_ASSESSED)
        self.assertEqual(
            result.reason,
            "permission denied while inspecting another account",
        )

    def test_unknown_malformed_empty_and_incomplete_output_is_not_assessed(self) -> None:
        outputs = (
            "",
            "some new sudo output format",
            "User alice may run the following commands on host-a:\n",
            "User alice may run the following commands on host-a:\n    (root)\n",
            "User alice may run the following commands on host-a:\n    RunAsUsers: root\n",
        )
        for output in outputs:
            with self.subTest(output=output):
                result = parse_sudo_listing("alice", output)
                self.assertIs(result.status, SudoPrivilegeStatus.NOT_ASSESSED)
                self.assertFalse(result.grants)

    def test_reported_account_mismatch_is_not_assessed(self) -> None:
        output = "User bob may run the following commands on host:\n (root) ALL\n"
        result = parse_sudo_listing("alice", output)

        self.assertIs(result.status, SudoPrivilegeStatus.NOT_ASSESSED)

    def test_control_sequences_are_not_parsed_as_policy(self) -> None:
        output = "User alice may run the following commands on host:\n\x1b[31m(root) ALL\n"
        result = parse_sudo_listing("alice", output)

        self.assertIs(result.status, SudoPrivilegeStatus.NOT_ASSESSED)


class SudoPrivilegeRuleTests(unittest.TestCase):
    def test_only_verified_uid_zero_and_sudo_grants_count_as_privileged(self) -> None:
        users = (
            User("root", 0, 0, ("root",), "/bin/sh", True),
            User("alice", 1000, 1000, ("users",), "/bin/sh", None),
            User("bob", 1001, 1001, ("users",), "/bin/sh", None),
        )
        results = (
            parse_sudo_listing(
                "alice",
                "User alice may run the following commands on host:\n (root) ALL\n",
            ),
            parse_sudo_listing(
                "bob", "", "sudo: a password is required", returncode=1
            ),
        )

        self.assertEqual(
            verified_privileged_accounts(users, results),
            ("root", "alice"),
        )


class CollectSudoPrivilegesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.users = (
            User("root", 0, 0, ("root",), "/bin/sh", True),
            User("alice", 1000, 1000, ("users",), "/bin/sh", None),
        )

    def test_sudo_unavailable_is_explicit(self) -> None:
        with (
            patch("vulpnix.collectors.sudo.shutil.which", return_value=None),
            patch("vulpnix.collectors.sudo.subprocess.run") as run,
        ):
            results = collect_sudo_privileges(self.users)

        self.assertTrue(all(result.status is SudoPrivilegeStatus.UNAVAILABLE for result in results))
        run.assert_not_called()

    def test_current_user_verified_uses_noninteractive_listing(self) -> None:
        completed = subprocess.CompletedProcess(
            ["sudo", "-n", "-l"],
            0,
            "User alice may run the following commands on host:\n (root) ALL\n",
            "",
        )
        with (
            patch("vulpnix.collectors.sudo.shutil.which", return_value="/usr/bin/sudo"),
            patch("vulpnix.collectors.sudo.os.geteuid", return_value=1000),
            patch("vulpnix.collectors.sudo.pwd.getpwuid") as getpwuid,
            patch("vulpnix.collectors.sudo.subprocess.run", return_value=completed) as run,
        ):
            getpwuid.return_value.pw_name = "alice"
            results = collect_sudo_privileges(self.users)

        self.assertIs(results[1].status, SudoPrivilegeStatus.PRIVILEGES_FOUND)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/sudo", "-n", "-l"])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertFalse(run.call_args.kwargs["check"])
        self.assertEqual(run.call_args.kwargs["timeout"], 5)

    def test_current_user_with_explicit_no_privileges_is_distinguished(self) -> None:
        completed = subprocess.CompletedProcess(
            ["sudo", "-n", "-l"],
            1,
            "",
            "User alice is not allowed to run sudo on host.\n",
        )
        with (
            patch("vulpnix.collectors.sudo.shutil.which", return_value="/usr/bin/sudo"),
            patch("vulpnix.collectors.sudo.os.geteuid", return_value=1000),
            patch("vulpnix.collectors.sudo.pwd.getpwuid") as getpwuid,
            patch("vulpnix.collectors.sudo.subprocess.run", return_value=completed),
        ):
            getpwuid.return_value.pw_name = "alice"
            results = collect_sudo_privileges(self.users)

        self.assertIs(results[1].status, SudoPrivilegeStatus.NO_PRIVILEGES)

    def test_password_required_failure_is_not_misread_as_no_privileges(self) -> None:
        completed = subprocess.CompletedProcess(
            ["sudo", "-n", "-l"], 1, "", "sudo: a password is required\n"
        )
        with (
            patch("vulpnix.collectors.sudo.shutil.which", return_value="/usr/bin/sudo"),
            patch("vulpnix.collectors.sudo.os.geteuid", return_value=1000),
            patch("vulpnix.collectors.sudo.pwd.getpwuid") as getpwuid,
            patch("vulpnix.collectors.sudo.subprocess.run", return_value=completed),
        ):
            getpwuid.return_value.pw_name = "alice"
            results = collect_sudo_privileges(self.users)

        self.assertIs(results[1].status, SudoPrivilegeStatus.NOT_ASSESSED)
        self.assertEqual(
            results[1].reason,
            "non-interactive listing requires authentication",
        )

    def test_non_root_skips_other_users_without_attempting_inspection(self) -> None:
        completed = subprocess.CompletedProcess(
            ["sudo", "-n", "-l"],
            1,
            "",
            "sudo: a password is required\n",
        )
        with (
            patch("vulpnix.collectors.sudo.shutil.which", return_value="/usr/bin/sudo"),
            patch("vulpnix.collectors.sudo.os.geteuid", return_value=1000),
            patch("vulpnix.collectors.sudo.pwd.getpwuid") as getpwuid,
            patch("vulpnix.collectors.sudo.subprocess.run", return_value=completed) as run,
        ):
            getpwuid.return_value.pw_name = "alice"
            results = collect_sudo_privileges(self.users)

        self.assertEqual(len(run.call_args_list), 1)
        self.assertNotIn("-U", run.call_args_list[0].args[0])
        self.assertIs(results[0].status, SudoPrivilegeStatus.NOT_ASSESSED)
        self.assertIn("skipped", results[0].reason)

    def test_root_can_inspect_other_user_and_permission_denial_is_not_assessed(self) -> None:
        current = subprocess.CompletedProcess(
            ["sudo", "-n", "-l"],
            0,
            "User root may run the following commands on host:\n (ALL) ALL\n",
            "",
        )
        other = subprocess.CompletedProcess(
            ["sudo", "-n", "-l", "-U", "alice"],
            1,
            "",
            "sudo: user root is not allowed to list privileges for alice\n",
        )
        with (
            patch("vulpnix.collectors.sudo.shutil.which", return_value="/usr/bin/sudo"),
            patch("vulpnix.collectors.sudo.os.geteuid", return_value=0),
            patch("vulpnix.collectors.sudo.pwd.getpwuid") as getpwuid,
            patch("vulpnix.collectors.sudo.subprocess.run", side_effect=(current, other)) as run,
        ):
            getpwuid.return_value.pw_name = "root"
            results = collect_sudo_privileges(self.users)

        self.assertEqual(run.call_args_list[1].args[0], ["/usr/bin/sudo", "-n", "-l", "-U", "alice"])
        self.assertIs(results[0].status, SudoPrivilegeStatus.PRIVILEGES_FOUND)
        self.assertIs(results[1].status, SudoPrivilegeStatus.NOT_ASSESSED)

    def test_root_successfully_inspects_other_user(self) -> None:
        completed = subprocess.CompletedProcess(
            ["sudo", "-n", "-l", "-U", "alice"],
            0,
            "User alice may run the following commands on host:\n (root) /usr/bin/id\n",
            "",
        )
        with (
            patch("vulpnix.collectors.sudo.shutil.which", return_value="/usr/bin/sudo"),
            patch("vulpnix.collectors.sudo.os.geteuid", return_value=0),
            patch("vulpnix.collectors.sudo.pwd.getpwuid") as getpwuid,
            patch("vulpnix.collectors.sudo.subprocess.run", side_effect=(
                subprocess.CompletedProcess(["sudo", "-n", "-l"], 0,
                    "User root may run the following commands on host:\n (ALL) ALL\n", ""),
                completed,
            )),
        ):
            getpwuid.return_value.pw_name = "root"
            results = collect_sudo_privileges(self.users)

        self.assertIs(results[1].status, SudoPrivilegeStatus.PRIVILEGES_FOUND)
        self.assertEqual(results[1].grants[0].allowed_commands, ("/usr/bin/id",))


if __name__ == "__main__":
    unittest.main()
