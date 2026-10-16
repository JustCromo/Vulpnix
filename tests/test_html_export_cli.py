"""Tests for HTML report export through the interactive CLI."""

import io
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import vulpnix.cli.app as app


class HTMLExportCLITests(unittest.TestCase):
    def setUp(self):
        self.result = SimpleNamespace(
            host=None,
            sections=[],
            findings=[],
            scope=None,
            coverage=None,
            review_items=[],
            privilege=None,
        )
        self.report = object()
        self.assessment = object()
        self.destination = Path("/tmp/report_scan_test.html")

    def test_full_scan_html_export(self):
        def run_scan(*, detailed=False):
            app._render_result(self.result, details=detailed)

        output = io.StringIO()
        with (
            patch.object(app, "_show_scan", side_effect=run_scan) as scan,
            patch.object(app, "ScanReport", return_value=self.report),
            patch.object(app, "assess_findings", return_value=self.assessment),
            patch.object(app, "save_html_report", return_value=self.destination) as save,
            patch.object(app, "render_scan_report") as terminal_renderer,
            redirect_stdout(output),
        ):
            self.assertTrue(app._dispatch_command("scan --format html"))

        scan.assert_called_once_with(detailed=False)
        save.assert_called_once_with(self.report, area=None)
        terminal_renderer.assert_not_called()
        self.assertIn(str(self.destination), output.getvalue())

    def test_area_export_supports_details_and_option_order(self):
        def run_ssh(*, detailed=False):
            app._render_result(self.result, details=detailed)

        output = io.StringIO()
        with (
            patch.object(app, "_show_ssh_assessment", side_effect=run_ssh) as ssh,
            patch.object(app, "ScanReport", return_value=self.report) as report_factory,
            patch.object(app, "assess_findings", return_value=self.assessment),
            patch.object(app, "save_html_report", return_value=self.destination) as save,
            patch.object(app, "render_scan_report") as terminal_renderer,
            redirect_stdout(output),
        ):
            self.assertTrue(
                app._dispatch_command("scan ssh --details --format html")
            )

        ssh.assert_called_once_with(detailed=True)
        save.assert_called_once_with(self.report, area="ssh")
        report_factory.assert_called_once()
        self.assertTrue(report_factory.call_args.kwargs["details"])
        terminal_renderer.assert_not_called()
        self.assertIn("HTML report saved:", output.getvalue())

    def test_markdown_and_json_exports_route_through_exporter(self):
        def run_scan(*, detailed=False):
            app._render_result(self.result, details=detailed)

        for output_format, label in (
            ("markdown", "Markdown"),
            ("json", "JSON"),
        ):
            with self.subTest(output_format=output_format):
                output = io.StringIO()
                with (
                    patch.object(app, "_show_scan", side_effect=run_scan) as scan,
                    patch.object(app, "ScanReport", return_value=self.report),
                    patch.object(app, "assess_findings", return_value=self.assessment),
                    patch.object(app, "save_report_export", return_value=self.destination) as save,
                    patch.object(app, "save_html_report") as html_save,
                    patch.object(app, "render_scan_report") as terminal_renderer,
                    redirect_stdout(output),
                ):
                    self.assertTrue(
                        app._dispatch_command(
                            f"scan --details --format {output_format}"
                        )
                    )

                scan.assert_called_once_with(detailed=True)
                save.assert_called_once_with(
                    self.report,
                    output_format,
                    area=None,
                )
                html_save.assert_not_called()
                terminal_renderer.assert_not_called()
                self.assertIn(f"{label} report saved:", output.getvalue())
                self.assertIn(str(self.destination), output.getvalue())

    def test_help_documents_all_export_formats(self):
        output = io.StringIO()
        with redirect_stdout(output):
            app._show_help()

        rendered = " ".join(output.getvalue().split())
        self.assertIn("--format html|markdown|json", rendered)

    def test_default_scan_still_uses_terminal_renderer(self):
        def run_scan(*, detailed=False):
            app._render_result(self.result, details=detailed)

        output = io.StringIO()
        with (
            patch.object(app, "_show_scan", side_effect=run_scan),
            patch.object(app, "ScanReport", return_value=self.report),
            patch.object(app, "assess_findings", return_value=self.assessment),
            patch.object(app, "save_html_report") as save,
            patch.object(
                app, "render_scan_report", return_value=["Terminal report"]
            ) as terminal_renderer,
            redirect_stdout(output),
        ):
            self.assertTrue(app._dispatch_command("scan --details"))

        save.assert_not_called()
        terminal_renderer.assert_called_once()
        self.assertEqual(output.getvalue(), "Terminal report\n")

    def test_unsupported_format_does_not_start_a_scan(self):
        output = io.StringIO()
        with (
            patch.object(app, "_show_scan") as scan,
            patch.object(app, "_show_ssh_assessment") as ssh,
            patch.object(app, "save_html_report") as save,
            patch.object(app, "save_report_export") as export,
            redirect_stdout(output),
        ):
            self.assertTrue(app._dispatch_command("scan --format csv"))

        scan.assert_not_called()
        ssh.assert_not_called()
        save.assert_not_called()
        export.assert_not_called()
        self.assertIn("Usage: scan", output.getvalue())

    def test_export_completions_are_available_for_all_formats(self):
        for output_format in ("html", "markdown", "json"):
            with self.subTest(output_format=output_format):
                self.assertIn(
                    f"scan ssh --format {output_format}",
                    app._command_completions(
                        f"scan ssh --format {output_format[0]}"
                    ),
                )


if __name__ == "__main__":
    unittest.main()
