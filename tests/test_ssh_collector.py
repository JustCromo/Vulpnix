import io
import subprocess
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix.collectors.ssh import (
    SSHCommandError,
    SSHGUnsupportedError,
    collect_ssh_config,
)
from vulpnix.models import SSHConfig, SSHConnectionContext, Service, SystemInfo


_SSH_CONFIG = "\n".join(
    (
        "permitrootlogin prohibit-password",
        "passwordauthentication yes",
        "permitemptypasswords no",
        "pubkeyauthentication yes",
    )
)


class CollectSSHConfigTests(unittest.TestCase):
    def _mock_sshd(self, result: subprocess.CompletedProcess[str]):
        which = patch("vulpnix.collectors.ssh.shutil.which", return_value="/usr/sbin/sshd")
        run = patch("vulpnix.collectors.ssh.subprocess.run", return_value=result)
        return which, run

    def test_supported_g_collects_effective_configuration(self) -> None:
        which, run = self._mock_sshd(
            subprocess.CompletedProcess(["sshd", "-G"], 0, _SSH_CONFIG, "")
        )
        with which, run as run_mock:
            config = collect_ssh_config()

        self.assertTrue(config.password_authentication)
        self.assertTrue(config.public_key_authentication)
        self.assertEqual(run_mock.call_args.args[0], ["/usr/sbin/sshd", "-G"])
        self.assertFalse(run_mock.call_args.kwargs["check"])
        self.assertFalse(run_mock.call_args.kwargs["shell"])

    def test_connection_context_is_passed_to_sshd_as_c_argument(self) -> None:
        connection = SSHConnectionContext(
            user="ivan",
            host="client.example",
            addr="192.0.2.20",
            laddr="192.0.2.10",
            lport=22,
        )
        which, run = self._mock_sshd(
            subprocess.CompletedProcess(["sshd", "-G"], 0, _SSH_CONFIG, "")
        )
        with which, run as run_mock:
            config = collect_ssh_config(connection)

        self.assertIs(config.connection_context, connection)
        self.assertEqual(
            run_mock.call_args.args[0],
            [
                "/usr/sbin/sshd",
                "-G",
                "-C",
                "user=ivan,host=client.example,addr=192.0.2.20,"
                "laddr=192.0.2.10,lport=22",
            ],
        )

    def test_unrecognized_g_is_reported_as_unsupported_across_message_variants(self) -> None:
        diagnostics = (
            "sshd: illegal option -- G",
            "Unknown option '-G'; see usage",
        )
        for diagnostic in diagnostics:
            with self.subTest(diagnostic=diagnostic):
                which, run = self._mock_sshd(
                    subprocess.CompletedProcess(
                        ["sshd", "-G"], 2, "usage: sshd", diagnostic
                    )
                )
                with which, run:
                    with self.assertRaises(SSHGUnsupportedError) as raised:
                        collect_ssh_config()

                self.assertEqual(raised.exception.returncode, 2)
                self.assertEqual(raised.exception.stderr, diagnostic)

    def test_other_nonzero_exit_remains_a_command_failure(self) -> None:
        which, run = self._mock_sshd(
            subprocess.CompletedProcess(
                ["sshd", "-G"], 255, "", "Unable to load sshd configuration"
            )
        )
        with which, run:
            with self.assertRaises(SSHCommandError) as raised:
                collect_ssh_config()

        self.assertNotIsInstance(raised.exception, SSHGUnsupportedError)
        self.assertEqual(raised.exception.returncode, 255)
        self.assertIn("Unable to load", raised.exception.stderr)

    def test_incomplete_success_output_is_malformed(self) -> None:
        incomplete = "\n".join(
            (
                "permitrootlogin no",
                "passwordauthentication no",
                "permitemptypasswords no",
            )
        )
        which, run = self._mock_sshd(
            subprocess.CompletedProcess(["sshd", "-G"], 0, incomplete, "")
        )
        with which, run:
            with self.assertRaisesRegex(ValueError, "PubkeyAuthentication"):
                collect_ssh_config()


class UnsupportedSSHCLIStatusTests(unittest.TestCase):
    def test_unsupported_g_is_not_assessed_and_runs_no_ssh_rules(self) -> None:
        unsupported = SSHGUnsupportedError(
            2, "usage: sshd", "sshd: illegal option -- G\x1b[31m"
        )
        output = io.StringIO()
        with (
            patch.object(app, "collect_system_info", return_value=SystemInfo()),
            patch.object(app, "collect_services", return_value=()),
            patch.object(app, "collect_ssh_config", side_effect=unsupported),
            patch.object(app, "check_ssh_root_login") as root_rule,
            patch.object(app, "check_ssh_password_authentication") as password_rule,
            patch.object(app, "check_ssh_empty_passwords") as empty_rule,
            patch.object(app, "check_ssh_public_key_authentication") as key_rule,
            redirect_stdout(output),
        ):
            app._show_scan()

        rendered = output.getvalue()
        self.assertIn("NOT ASSESSED / Unavailable", rendered)
        self.assertIn("sshd -G is not supported", rendered)
        self.assertIn("exit 2", rendered)
        self.assertNotIn("\x1b[31m", rendered)
        self.assertNotRegex(rendered, r"\[(?:PASS|FAIL)\]")
        root_rule.assert_not_called()
        password_rule.assert_not_called()
        empty_rule.assert_not_called()
        key_rule.assert_not_called()


class SSHCommandTests(unittest.TestCase):
    def test_help_lists_ssh_as_a_scan_subcommand(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            app._show_help()

        self.assertIn("scan host  Host facts only", output.getvalue())
        self.assertIn("scan service  Services and startup state", output.getvalue())
        self.assertIn("scan ssh  SSH assessment only", output.getvalue())
        self.assertNotIn("scan --ssh", output.getvalue())

    def test_scan_ssh_dispatches_to_ssh_assessment(self) -> None:
        with patch.object(app, "_show_ssh_assessment") as ssh_assessment:
            keep_running = app._dispatch_command("scan ssh")

        self.assertTrue(keep_running)
        ssh_assessment.assert_called_once_with()

    def test_scan_host_shows_host_facts_only(self) -> None:
        info = SystemInfo(distribution="Example Linux", distribution_version="1")
        with (
            patch.object(app, "collect_system_info", return_value=info) as collect,
            patch.object(app, "_show_system_info") as show_info,
            patch.object(app, "collect_services") as services,
            patch.object(app, "_show_ssh_assessment") as ssh,
            redirect_stdout(io.StringIO()),
        ):
            keep_running = app._dispatch_command("scan host")

        self.assertTrue(keep_running)
        collect.assert_called_once_with()
        show_info.assert_called_once_with(info, "HOST DETAILS")
        services.assert_not_called()
        ssh.assert_not_called()

    def test_scan_service_shows_service_and_startup_state_only(self) -> None:
        units = (Service(name="example.service", state="active", unit_file_state="enabled"),)
        with (
            patch.object(app, "collect_services", return_value=units) as collect,
            patch.object(app, "_show_services") as show_services,
            patch.object(app, "collect_system_info") as host,
            patch.object(app, "_show_ssh_assessment") as ssh,
            redirect_stdout(io.StringIO()),
        ):
            keep_running = app._dispatch_command("scan service")

        self.assertTrue(keep_running)
        collect.assert_called_once_with()
        show_services.assert_called_once_with(units)
        host.assert_not_called()
        ssh.assert_not_called()

    def test_scan_still_dispatches_to_full_assessment(self) -> None:
        info = SystemInfo(
            hostname="example-host",
            distribution="Example Linux",
            architecture="x86_64",
        )
        ssh_config = SSHConfig(
            permit_root_login="no",
            password_authentication=False,
            permit_empty_passwords=False,
            public_key_authentication=True,
        )
        output = io.StringIO()
        with (
            patch.object(app, "collect_system_info", return_value=info) as host,
            patch.object(app, "collect_services", return_value=()) as services,
            patch.object(app, "collect_ssh_config", return_value=ssh_config) as ssh,
            redirect_stdout(output),
        ):
            keep_running = app._dispatch_command("scan")

        self.assertTrue(keep_running)
        host.assert_called_once_with()
        services.assert_called_once_with()
        ssh.assert_called_once_with()
        self.assertLess(output.getvalue().index("ATTENTION"), output.getvalue().index("DETAILS"))
        self.assertIn("example-host", output.getvalue())
        self.assertIn("Password authentication", output.getvalue())

    def test_ssh_only_assessment_uses_global_configuration(self) -> None:
        config = SSHConfig(
            permit_root_login="prohibit-password",
            password_authentication=True,
            permit_empty_passwords=False,
            public_key_authentication=True,
        )
        with (
            patch.object(app, "collect_ssh_config", return_value=config) as collect,
            patch.object(app, "_show_ssh_config") as show_config,
            patch.object(app, "check_ssh_root_login", return_value=()),
            patch.object(app, "check_ssh_password_authentication", return_value=()),
            patch.object(app, "check_ssh_empty_passwords", return_value=()),
            patch.object(app, "check_ssh_public_key_authentication", return_value=()),
            patch.object(app, "_show_findings") as show_findings,
        ):
            app._show_ssh_assessment()

        collect.assert_called_once_with()
        show_config.assert_called_once_with(config)
        show_findings.assert_called_once_with(())


class CommandCompletionTests(unittest.TestCase):
    def test_single_tab_completes_a_unique_subcommand(self) -> None:
        keys = iter(("s", "c", "a", "n", " ", "h", "\t", "\n"))
        with patch.object(app, "read_key", side_effect=lambda **_kwargs: next(keys)):
            with patch.object(app, "_render_shell"):
                command, _ = app._read_command([], [], 0)

        self.assertEqual(command, "scan host")

    def test_double_tab_lists_matching_suggestions(self) -> None:
        keys = iter(("s", "c", "a", "n", " ", "\t", "\t", "\n"))
        output_lines: list[str] = []
        with patch.object(app, "read_key", side_effect=lambda **_kwargs: next(keys)):
            with patch.object(app, "_render_shell") as render_shell:
                command, _ = app._read_command(output_lines, [], 0)

        self.assertEqual(command, "scan")
        self.assertEqual(output_lines, [])
        suggestions = render_shell.call_args.args[4]
        self.assertIn("SUGGESTIONS", suggestions[0])
        self.assertIn("  scan host", suggestions)
        self.assertIn("  scan service", suggestions)
        self.assertIn("  scan ssh", suggestions)

    def test_suggestions_render_below_the_prompt(self) -> None:
        output = io.StringIO()
        with (
            patch.object(app, "terminal_size", return_value=(80, 8)),
            patch.object(app.sys, "stdout", output),
        ):
            app._render_shell(
                [], "scan ", 5, 0, (app.accent("SUGGESTIONS"), "  scan host")
            )

        rendered = output.getvalue()
        self.assertLess(rendered.index("vulpnix> scan"), rendered.index("SUGGESTIONS"))
        self.assertLess(rendered.index("SUGGESTIONS"), rendered.index("scan host"))


if __name__ == "__main__":
    unittest.main()
