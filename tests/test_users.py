"""Tests for local user and group inventory."""

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix_test_support import patch_supplementary_collectors
from vulpnix.collectors.users import collect_local_users
from vulpnix.models import SudoGrant, SudoPrivilege, SudoPrivilegeStatus
from vulpnix.parsers.users import parse_local_users


PASSWD = "\n".join(
    (
        "root:x:0:0:Root:/root:/bin/sh",
        "service:x:0:10:Service:/nonexistent:/usr/sbin/nologin",
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
        "bob:x:1001:1001:Bob:/home/bob:",
    )
)
GROUP = "\n".join(
    (
        "root:x:0:",
        "users:x:1000:",
        "operators:x:2000:alice,bob",
        "service-group:x:10:service",
    )
)
SHADOW = "\n".join(
    (
        "root:$6$root-hash:1:0:99999:7::: ",
        "service:!:1:0:99999:7::: ",
        "alice:$6$alice-hash:1:0:99999:7::: ",
        "bob::1:0:99999:7::: ",
    )
)


class ParseLocalUsersTests(unittest.TestCase):
    def test_normal_users_uid_zero_groups_shells_and_account_state(self) -> None:
        users = parse_local_users(PASSWD, GROUP, SHADOW)
        by_name = {user.username: user for user in users}

        self.assertEqual(by_name["alice"].uid, 1000)
        self.assertEqual(by_name["alice"].gid, 1000)
        self.assertEqual(by_name["alice"].groups, ("users", "operators"))
        self.assertEqual(by_name["alice"].shell, "/bin/bash")
        self.assertIsNone(by_name["alice"].account_state)
        self.assertIsNone(by_name["alice"].privileged)
        self.assertTrue(by_name["root"].privileged)
        self.assertEqual(by_name["service"].groups, ("service-group",))
        self.assertEqual(by_name["service"].account_state, "password locked")
        self.assertIsNone(by_name["bob"].shell)
        self.assertEqual(by_name["bob"].account_state, "password field empty")

    def test_multiple_uid_zero_accounts_are_identified_without_findings(self) -> None:
        users = parse_local_users(PASSWD, GROUP)
        uid_zero = [user for user in users if user.uid == 0]

        self.assertEqual([user.username for user in uid_zero], ["root", "service"])
        self.assertTrue(all(user.privileged is True for user in uid_zero))
        # UID 0 is collected as a fact; no condition here establishes a vulnerability.

    def test_missing_group_and_shadow_information_remains_unknown(self) -> None:
        users = parse_local_users(PASSWD, None, None)
        by_name = {user.username: user for user in users}

        self.assertIsNone(by_name["alice"].groups)
        self.assertIsNone(by_name["alice"].account_state)
        self.assertIsNone(by_name["alice"].privileged)

    def test_incomplete_passwd_record_is_a_parser_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "Malformed passwd"):
            parse_local_users("alice:x:1000:1000:Alice:/home/alice", GROUP)

    def test_invalid_group_gid_is_a_parser_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "Invalid group GID"):
            parse_local_users(PASSWD, "users:x:bad:alice")


class CollectLocalUsersTests(unittest.TestCase):
    def _write_databases(self, directory: str) -> tuple[Path, Path, Path]:
        paths = tuple(Path(directory) / name for name in ("passwd", "group", "shadow"))
        paths[0].write_text(PASSWD, encoding="utf-8")
        paths[1].write_text(GROUP, encoding="utf-8")
        paths[2].write_text(SHADOW, encoding="utf-8")
        return paths

    def test_collects_local_files_and_does_not_require_sudo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            passwd, group, shadow = self._write_databases(directory)
            with patch.dict(os.environ, {"PATH": ""}):
                users = collect_local_users(passwd, group, shadow)

        self.assertEqual(len(users), 4)

    def test_unreadable_optional_databases_are_not_guessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            passwd, _group, _shadow = self._write_databases(directory)
            users = collect_local_users(passwd, Path(directory) / "missing-group", Path(directory) / "missing-shadow")

        self.assertTrue(all(user.groups is None for user in users))
        self.assertTrue(all(user.account_state is None for user in users))

    def test_passwd_collector_failure_is_reported(self) -> None:
        with self.assertRaises(FileNotFoundError):
            collect_local_users(Path("/path/that/does/not/exist"))


class UsersCLItests(unittest.TestCase):
    def test_scan_users_dispatches_only_user_assessment(self) -> None:
        with (
            patch.object(app, "_show_users_assessment") as show_users,
            patch.object(app, "collect_ssh_config") as ssh,
            patch.object(app, "collect_services") as services,
        ):
            self.assertTrue(app._dispatch_command("scan users"))

        show_users.assert_called_once_with(detailed=False)
        ssh.assert_not_called()
        services.assert_not_called()

    def test_scan_users_shows_security_summary_not_full_inventory(self) -> None:
        output = io.StringIO()
        users = tuple(
            user
            for user in parse_local_users(PASSWD, GROUP)
            if user.username != "service"
        )
        with (
            patch.object(app, "collect_local_users", return_value=users),
            patch.object(
                app,
                "collect_sudo_privileges",
                return_value=(
                    SudoPrivilege("root", SudoPrivilegeStatus.PRIVILEGES_FOUND,
                                  grants=(SudoGrant(("ALL",), None, ("ALL",), ()),)),
                    SudoPrivilege("alice", SudoPrivilegeStatus.NOT_ASSESSED,
                                  reason="permission denied while inspecting another account"),
                    SudoPrivilege("bob", SudoPrivilegeStatus.NOT_ASSESSED,
                                  reason="other-account inspection skipped because current process permissions are insufficient"),
                ),
            ),
            patch.object(app, "terminal_size", return_value=(80, 24)),
            contextlib.redirect_stdout(output),
        ):
            app._dispatch_command("scan users")

        rendered = output.getvalue()
        normalized = " ".join(rendered.split())
        self.assertIn("Local accounts", rendered)
        self.assertIn("UID 0 accounts", rendered)
        self.assertIn("Privileged accounts", rendered)
        self.assertIn("Only one UID 0 account detected: root", rendered)
        self.assertIn("1 account: permission denied while inspecting another account", normalized)
        self.assertIn("1 account: other-account inspection skipped; current process lacks permission", normalized)
        self.assertIn("Sudo access verified for 1 account", rendered)
        self.assertIn("3 accounts could not be evaluated for account state", rendered)
        self.assertIn("DETAILS", rendered)
        self.assertIn("root", rendered)
        self.assertNotIn("alice · UID 1000", rendered)
        self.assertNotIn("bob · UID 1001", rendered)
        self.assertNotIn("ACCOUNT INVENTORY", rendered)
        self.assertNotIn("[REVIEW]", rendered)
        self.assertNotIn("[PASS]", rendered)
        self.assertNotIn("[FAIL]", rendered)

    def test_scan_users_details_shows_complete_inventory(self) -> None:
        output = io.StringIO()
        users = parse_local_users(PASSWD, GROUP)
        with (
            patch.object(app, "collect_local_users", return_value=users),
            patch.object(app, "collect_sudo_privileges", return_value=()),
            patch.object(app, "terminal_size", return_value=(100, 30)),
            contextlib.redirect_stdout(output),
        ):
            app._dispatch_command("scan users --details")

        rendered = output.getvalue()
        self.assertIn("ACCOUNT INVENTORY", rendered)
        self.assertIn("root · UID 0", rendered)
        self.assertIn("alice · UID 1000", rendered)
        self.assertIn("bob · UID 1001", rendered)

    def test_user_inventory_uses_verified_sudo_privilege_status(self) -> None:
        output = io.StringIO()
        users = tuple(
            user for user in parse_local_users(PASSWD, GROUP)
            if user.username in {"root", "alice", "bob"}
        )
        sudo_results = (
            SudoPrivilege(
                "alice",
                SudoPrivilegeStatus.PRIVILEGES_FOUND,
                grants=(SudoGrant(("ALL",), None, ("ALL",), ()),),
            ),
            SudoPrivilege(
                "bob",
                SudoPrivilegeStatus.NO_PRIVILEGES,
                reason="sudo explicitly reported no allowed commands",
            ),
        )

        with (
            patch.object(app, "collect_local_users", return_value=users),
            patch.object(app, "collect_sudo_privileges", return_value=sudo_results),
            patch.object(app, "terminal_size", return_value=(160, 30)),
            contextlib.redirect_stdout(output),
        ):
            app._dispatch_command("scan users --details")

        normalized = " ".join(output.getvalue().split())
        self.assertIn("alice · UID 1000", normalized)
        self.assertIn("alice · UID 1000 · GID 1000 · groups: users, operators · shell: /bin/bash · privileged: yes", normalized)
        self.assertIn("bob · UID 1001 · GID 1001 · groups: Unavailable · shell: Unavailable · privileged: no", normalized)


    def test_additional_uid_zero_accounts_are_reviewed_not_marked_as_findings(self) -> None:
        output = io.StringIO()
        with (
            patch.object(app, "collect_local_users", return_value=parse_local_users(PASSWD, GROUP)),
            patch.object(app, "collect_sudo_privileges", return_value=()),
            patch.object(app, "collect_sensitive_file_metadata", return_value=()),
            patch.object(app, "terminal_size", return_value=(100, 30)),
            contextlib.redirect_stdout(output),
        ):
            app._dispatch_command("scan users")

        rendered = output.getvalue()
        self.assertIn("Additional UID 0 accounts detected: service", rendered)
        self.assertIn("Review authorization for additional UID 0 accounts: service", rendered)
        self.assertNotIn("[FAIL]", rendered)
        self.assertNotIn("[PASS]", rendered)

    def test_full_scan_includes_users_section(self) -> None:
        from vulpnix.models import SSHConfig, SystemInfo

        output = io.StringIO()
        with (
            patch_supplementary_collectors(app),
            patch.object(app, "collect_system_info", return_value=SystemInfo()),
            patch.object(app, "collect_local_users", return_value=parse_local_users(PASSWD, GROUP)),
            patch.object(app, "collect_sudo_privileges", return_value=()),
            patch.object(app, "collect_services", return_value=()),
            patch.object(
                app,
                "collect_ssh_config",
                return_value=SSHConfig("no", False, False, True),
            ),
            contextlib.redirect_stdout(output),
        ):
            app._show_scan()

        self.assertIn("USERS", output.getvalue())
        self.assertIn("• root", output.getvalue())
        self.assertNotIn("alice · UID 1000", output.getvalue())


if __name__ == "__main__":
    unittest.main()
