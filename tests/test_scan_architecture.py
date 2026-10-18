import unittest
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix.cli.report import ReportSection
from vulpnix.scan.result import ScanResult


def section_result(title):
    return ScanResult(sections=(ReportSection(title),), scope=(title.lower(),))


class FullScanCompositionTests(unittest.TestCase):
    def test_full_scan_lists_every_area_in_presentation_order(self):
        with (
            patch.object(app, "_run_services_result", return_value=section_result("SERVICES")),
            patch.object(app, "_run_users_result", return_value=section_result("USERS")),
            patch.object(app, "_run_filesystem_result", return_value=section_result("FILESYSTEM")),
            patch.object(app, "_run_ssh_config_result", return_value=section_result("SSH")),
            patch.object(app, "_run_hardening_result", return_value=section_result("KERNEL HARDENING")),
            patch.object(app, "_run_network_result", return_value=section_result("NETWORK")),
            patch.object(app, "_run_ssh_host_key_result", return_value=section_result("SSH HOST-KEY")),
            patch.object(app, "_run_storage_result", return_value=section_result("STORAGE")),
            patch.object(app, "_run_unit_files_result", return_value=section_result("UNIT FILES")),
            patch.object(app, "_run_package_result", return_value=section_result("PACKAGES")),
            patch.object(app, "_render_result") as render,
        ):
            app._show_scan()

        result = render.call_args.args[0]
        titles = [section.title for section in result.sections]
        self.assertEqual(titles[0], "SYSTEM")
        self.assertEqual(
            titles[1:],
            ["SERVICES", "USERS", "FILESYSTEM", "SSH", "KERNEL HARDENING", "NETWORK",
             "SSH HOST-KEY", "STORAGE", "UNIT FILES", "PACKAGES"],
        )

    def test_full_scan_scope_keeps_its_legacy_order(self):
        with (
            patch.object(app, "_run_services_result", return_value=section_result("SERVICES")),
            patch.object(app, "_run_users_result", return_value=section_result("USERS")),
            patch.object(app, "_run_filesystem_result", return_value=section_result("FILESYSTEM")),
            patch.object(app, "_run_ssh_config_result", return_value=section_result("SSH")),
            patch.object(app, "_run_hardening_result", return_value=section_result("KERNEL HARDENING")),
            patch.object(app, "_run_network_result", return_value=section_result("NETWORK")),
            patch.object(app, "_run_ssh_host_key_result", return_value=section_result("SSH HOST-KEY")),
            patch.object(app, "_run_storage_result", return_value=section_result("STORAGE")),
            patch.object(app, "_run_unit_files_result", return_value=section_result("UNIT FILES")),
            patch.object(app, "_run_package_result", return_value=section_result("PACKAGES")),
            patch.object(app, "_render_result") as render,
        ):
            app._show_scan()

        scope = render.call_args.args[0].scope
        self.assertEqual(scope[:5], ("system facts", "users", "services", "filesystem metadata", "set-ID files"))
        self.assertEqual(len(scope), len(set(scope)))


if __name__ == "__main__":
    unittest.main()
