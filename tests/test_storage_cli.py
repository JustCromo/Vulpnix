"""CLI integration tests for the M7 storage assessment."""

import unittest
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix.cli.report import ReportSection
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.findings import Finding, FindingStatus
from vulpnix.models.storage import (
    MountedFilesystem,
    StorageSnapshot,
    StorageStatus,
)
from vulpnix.scan.result import ScanResult


def base_result(title="EXISTING FILESYSTEM"):
    return ScanResult(
        sections=(ReportSection(title),),
        scope=("existing filesystem checks",),
        coverage=AssessmentCoverage.COMPLETE,
        review_items=0,
    )


def storage_result():
    finding = Finding(
        rule_id="STORAGE-SPACE-LOW-VAR",
        title="Low available storage on /var (2.0% available)",
        evidence="mount=/var; available_percent=2.0",
        explanation="Available storage is below the configured review threshold.",
        recommendation="Review storage usage and retention policies.",
        status=FindingStatus.REVIEW,
    )
    return ScanResult(
        sections=(ReportSection("DISK & FILESYSTEM CAPACITY"),),
        findings=(finding,),
        scope=("storage capacity",),
        coverage=AssessmentCoverage.COMPLETE,
        review_items=0,
    )


class StorageCliIntegrationTests(unittest.TestCase):
    def test_filesystem_command_includes_m7_storage_result(self):
        base = base_result()
        storage = storage_result()
        fake_orchestrator = type(
            "FakeOrchestrator",
            (),
            {"run_filesystem": lambda self, **kwargs: base},
        )()

        with (
            patch.object(app, "_make_orchestrator", return_value=fake_orchestrator),
            patch.object(app, "_run_storage_result", return_value=storage) as run_storage,
            patch.object(app, "_render_result") as render,
        ):
            app._show_filesystem_assessment()

        run_storage.assert_called_once_with(details=False)
        result = render.call_args.args[0]
        self.assertIn(
            "DISK & FILESYSTEM CAPACITY",
            tuple(section.title for section in result.sections),
        )
        self.assertTrue(
            any(f.rule_id == "STORAGE-SPACE-LOW-VAR" for f in result.findings)
        )


    def test_full_scan_includes_m7_storage_result(self):
        base = base_result("SYSTEM")
        storage = storage_result()
        empty = ScanResult()
        fake_orchestrator = type(
            "FakeOrchestrator",
            (),
            {"run_full_scan": lambda self, **kwargs: base},
        )()

        with (
            patch.object(app, "_make_orchestrator", return_value=fake_orchestrator),
            patch.object(app, "_run_hardening_result", return_value=empty),
            patch.object(app, "_run_network_result", return_value=empty),
            patch.object(app, "_run_ssh_host_key_result", return_value=empty),
            patch.object(app, "_run_storage_result", return_value=storage) as run_storage,
            patch.object(app, "_run_package_result", return_value=empty),
            patch.object(app, "_render_result") as render,
        ):
            app._show_scan()

        run_storage.assert_called_once_with(details=False)
        result = render.call_args.args[0]
        self.assertIn(
            "DISK & FILESYSTEM CAPACITY",
            tuple(section.title for section in result.sections),
        )
        self.assertTrue(
            any(f.rule_id == "STORAGE-SPACE-LOW-VAR" for f in result.findings)
        )

    def test_filesystem_details_are_forwarded_to_storage(self):
        base = base_result()
        storage = storage_result()
        fake_orchestrator = type(
            "FakeOrchestrator",
            (),
            {"run_filesystem": lambda self, **kwargs: base},
        )()

        with (
            patch.object(app, "_make_orchestrator", return_value=fake_orchestrator),
            patch.object(app, "_run_storage_result", return_value=storage) as run_storage,
            patch.object(app, "_render_result"),
        ):
            app._show_filesystem_assessment(detailed=True)

        run_storage.assert_called_once_with(details=True)

    def test_storage_report_detail_lists_mount_metadata(self):
        filesystem = MountedFilesystem(
            mount_point="/data",
            fs_type="ext4",
            source="/dev/test",
            mount_options=("rw", "nodev"),
            super_options=("rw",),
            total_bytes=1024 * 1024,
            free_bytes=512 * 1024,
            available_bytes=256 * 1024,
            total_inodes=1000,
            free_inodes=600,
            available_inodes=500,
            status=StorageStatus.COLLECTED,
        )
        snapshot = StorageSnapshot(
            (filesystem,),
            StorageStatus.COLLECTED,
        )
        section = app._storage_report_section(
            snapshot,
            (),
            details=True,
        )
        self.assertIn("Mount inventory (expanded):", section.items_label)
        self.assertTrue(any("/data" in item for item in section.items))
        self.assertTrue(any("ext4" in item for item in section.items))
        self.assertTrue(any("nodev" in item for item in section.items))


if __name__ == "__main__":
    unittest.main()
