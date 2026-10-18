"""Deterministic tests for bounded SUID/SGID discovery and assessment."""

import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix.areas.host import area as host_area
from vulpnix.areas.ssh import area as ssh_area
from vulpnix_test_support import patch_supplementary_collectors
from vulpnix.collectors import setid
from vulpnix.collectors.setid import collect_setid_files
from vulpnix.findings import FindingStatus
from vulpnix.models import (
    CoverageStatus,
    FileMetadata,
    FilesystemCoverage,
    SetIdFile,
    SSHConfig,
    SystemInfo,
)
from vulpnix.parsers.mountinfo import parse_mountinfo
from vulpnix.rules.filesystem import assess_setid_files


def elf_header() -> bytes:
    return b"\x7fELF\x02\x01\x01" + bytes(9) + b"\x02\x00\x3e\x00\x01\x00\x00\x00"


def mountinfo(root: str, options: str = "rw") -> str:
    encoded = root.replace("\\", "\\134").replace(" ", "\\040")
    return f"31 22 0:28 / {encoded} {options} - tmpfs tmpfs rw\n"


class SetIdCollectorTests(unittest.TestCase):
    def collect(self, root: str, *, options: str = "rw", **kwargs: object):
        with (
            patch.object(setid, "read_id_map", return_value=((0, 2**32),)),
            patch.object(setid, "read_overflow_id", return_value=65534),
        ):
            return collect_setid_files(
                roots=(root,), mountinfo_text=mountinfo(root, options), **kwargs
            )

    def test_collects_regular_setid_elf_metadata_without_reading_more_than_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ordinary-suid"
            path.write_bytes(elf_header() + b"not-read" * 500)
            path.chmod(0o4755)
            original_read = os.read
            requested_sizes: list[int] = []

            def bounded_read(fd: int, size: int) -> bytes:
                requested_sizes.append(size)
                return original_read(fd, size)

            with patch.object(setid.os, "read", side_effect=bounded_read):
                coverage = self.collect(directory)

        self.assertEqual(coverage.status, CoverageStatus.COLLECTED)
        self.assertEqual(len(coverage.files), 1)
        self.assertEqual(coverage.files[0].metadata.mode, 0o4755)
        self.assertEqual(coverage.files[0].metadata.type, "regular file")
        self.assertTrue(coverage.files[0].is_elf)
        self.assertEqual(coverage.files[0].mount_options, ("rw",))
        self.assertEqual(requested_sizes, [24])

    def test_symlink_and_special_files_are_not_followed_or_included(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "target"
            target.write_bytes(elf_header())
            target.chmod(0o4755)
            (Path(directory) / "alias").symlink_to(target)
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo, 0o4755)
            coverage = self.collect(directory)
        self.assertEqual(coverage.files, ())
        self.assertEqual(coverage.status, CoverageStatus.COLLECTED)

    def test_nested_mount_point_is_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mounted = root / "nested"
            mounted.mkdir()
            binary = mounted / "mounted-suid"
            binary.write_bytes(elf_header())
            binary.chmod(0o4755)
            text = mountinfo(directory) + mountinfo(str(mounted))
            with (
                patch.object(setid, "read_id_map", return_value=((0, 2**32),)),
                patch.object(setid, "read_overflow_id", return_value=65534),
            ):
                coverage = collect_setid_files(roots=(directory,), mountinfo_text=text)
        self.assertEqual(coverage.files, ())
        self.assertEqual(coverage.status, CoverageStatus.COLLECTED)

    def test_inaccessible_subdirectory_marks_coverage_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            child = Path(directory) / "restricted"
            child.mkdir()
            child_inode = child.stat().st_ino
            original_scandir = os.scandir

            def controlled_scandir(path_or_fd: str | int):
                if isinstance(path_or_fd, int) and os.fstat(path_or_fd).st_ino == child_inode:
                    raise PermissionError("denied by test")
                return original_scandir(path_or_fd)

            with (
                patch.object(setid, "read_id_map", return_value=((0, 2**32),)),
                patch.object(setid, "read_overflow_id", return_value=65534),
                patch.object(setid.os, "scandir", side_effect=controlled_scandir),
            ):
                coverage = collect_setid_files(
                    roots=(directory,), mountinfo_text=mountinfo(directory)
                )
        self.assertEqual(coverage.status, CoverageStatus.PARTIAL)
        self.assertTrue(any("directory could not be read" in item for item in coverage.review))

    def test_entry_budget_is_enforced_and_coverage_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for index in range(20):
                (Path(directory) / f"entry-{index:02d}").touch()
            coverage = self.collect(directory, max_entries=3)
        self.assertEqual(coverage.status, CoverageStatus.PARTIAL)
        self.assertEqual(coverage.entries_examined, 3)
        self.assertTrue(any("entry budget exceeded" in item for item in coverage.review))

    def test_time_budget_is_enforced_and_coverage_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for index in range(20):
                (Path(directory) / f"entry-{index:02d}").touch()

            class Clock:
                value = 0.0

                def __call__(self) -> float:
                    self.value += 0.1
                    return self.value

            coverage = self.collect(directory, max_seconds=0.15, clock=Clock())
        self.assertEqual(coverage.status, CoverageStatus.PARTIAL)
        self.assertLessEqual(coverage.entries_examined, 1)
        self.assertTrue(any("time budget exceeded" in item for item in coverage.review))

    def test_unavailable_or_malformed_mountinfo_prevents_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            coverage = collect_setid_files(
                roots=(directory,), mountinfo_text="not mountinfo"
            )
        self.assertEqual(coverage.status, CoverageStatus.NOT_ASSESSED)
        self.assertEqual(coverage.entries_examined, 0)
        self.assertIn("mount boundaries", coverage.review[0])

    def test_mountinfo_parser_unescapes_paths_and_preserves_options(self) -> None:
        parsed = parse_mountinfo("31 22 0:28 / /opt/tools\\040area rw,nosuid - ext4 /dev/test rw\n")
        self.assertEqual(parsed[0].mount_point, "/opt/tools area")
        self.assertIn("nosuid", parsed[0].options)

    def test_changed_file_is_not_assessed_after_no_follow_open(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(elf_header())
            path.chmod(0o4755)
            discovered = os.stat(path, follow_symlinks=False)
            parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(setid, "_snapshot", side_effect=[(1,), (2,)]):
                    is_elf, reason = setid._inspect_elf_signature(
                        parent_fd, "binary", discovered
                    )
            finally:
                os.close(parent_fd)
        self.assertIsNone(is_elf)
        self.assertIn("changed between discovery", reason)

    def test_incomplete_or_malformed_elf_header_is_not_assessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad-elf"
            path.write_bytes(b"\x7fELF")
            path.chmod(0o4755)
            discovered = os.stat(path, follow_symlinks=False)
            parent_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                incomplete = setid._inspect_elf_signature(parent_fd, "bad-elf", discovered)
                path.write_bytes(elf_header()[:23])
                malformed_stat = os.stat(path, follow_symlinks=False)
                malformed = setid._inspect_elf_signature(parent_fd, "bad-elf", malformed_stat)
            finally:
                os.close(parent_fd)
        self.assertIsNone(incomplete[0])
        self.assertIn("incomplete", incomplete[1])
        self.assertIsNone(malformed[0])
        self.assertIn("incomplete", malformed[1])


class SetIdRuleTests(unittest.TestCase):
    def file(
        self,
        path: str,
        *,
        mode: int = 0o4755,
        uid: int | None = 0,
        gid: int | None = 0,
        is_elf: bool | None = True,
        options: tuple[str, ...] | None = (),
        file_type: str = "regular file",
    ) -> SetIdFile:
        return SetIdFile(
            FileMetadata(path, uid, gid, mode, 8, file_type),
            is_elf,
            options,
        )

    def assessment(self, *files: SetIdFile):
        return assess_setid_files(
            FilesystemCoverage(
                tuple(files), CoverageStatus.COLLECTED, ("/usr",), 1, 0.01
            )
        )

    def test_ordinary_root_owned_suid_and_sgid_are_not_vulnerabilities(self) -> None:
        result = self.assessment(
            self.file("/usr/bin/ordinary-suid"),
            self.file("/usr/bin/ordinary-sgid", mode=0o2755, gid=42),
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(result.active, 2)

    def test_world_writable_active_suid_elf_is_fail_without_group_write(self) -> None:
        result = self.assessment(self.file("/usr/local/bin/writable", mode=0o4713))
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.status, FindingStatus.FAIL)
        self.assertEqual(finding.rule_id, "FS-SETID-WORLD-WRITE-001")
        self.assertEqual(0o4713 & 0o020, 0)
        self.assertNotEqual(0o4713 & 0o002, 0)

    def test_group_writable_alone_is_not_a_finding(self) -> None:
        result = self.assessment(self.file("/usr/local/bin/group-write", mode=0o4775))
        self.assertEqual(result.findings, ())

    def test_nosuid_or_noexec_mount_disables_finding(self) -> None:
        for options in (("rw", "nosuid"), ("rw", "noexec")):
            with self.subTest(options=options):
                result = self.assessment(
                    self.file("/usr/local/bin/writable", mode=0o4713, options=options)
                )
                self.assertEqual(result.findings, ())
                self.assertEqual(result.disabled, 1)

    def test_missing_ownership_signature_or_mount_context_is_review_only(self) -> None:
        result = self.assessment(
            self.file("/usr/a", uid=None),
            self.file("/usr/b", is_elf=None),
            self.file("/usr/c", options=None),
            self.file("/usr/d", file_type="directory"),
        )
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.review), 4)

    def test_unknown_coverage_is_not_a_finding(self) -> None:
        coverage = FilesystemCoverage(
            (), CoverageStatus.NOT_ASSESSED, ("/usr",), 0, 0.0,
            ("mount boundaries unavailable",),
        )
        result = assess_setid_files(coverage)
        self.assertEqual(result.findings, ())
        self.assertIn("mount boundaries unavailable", result.review)


class SetIdCliTests(unittest.TestCase):
    def test_filesystem_output_is_concise_and_marks_verified_finding_fail(self) -> None:
        item = SetIdFile(
            FileMetadata("/usr/local/bin/writable", 0, 0, 0o4713, 99, "regular file"),
            True,
            ("rw",),
        )
        ordinary = tuple(
            SetIdFile(
                FileMetadata(f"/usr/bin/ordinary-{index}", 0, 0, 0o4755, 20, "regular file"),
                True,
                ("rw",),
            )
            for index in range(10)
        )
        coverage = FilesystemCoverage(
            (item, *ordinary), CoverageStatus.COLLECTED, ("/usr",), 40, 0.02
        )
        output = io.StringIO()
        with (
            patch.object(app, "collect_sensitive_file_metadata", return_value=()),
            patch.object(app, "collect_setid_files", return_value=coverage),
            patch.object(app, "terminal_size", return_value=(100, 30)),
            contextlib.redirect_stdout(output),
        ):
            app._dispatch_command("scan filesystem")
        rendered = output.getvalue()
        self.assertIn("[FAIL] Active set-ID ELF file is world-writable", rendered)
        self.assertNotIn("FS-SETID-WORLD-WRITE-001", rendered)
        self.assertIn(item.metadata.path, rendered)
        self.assertIn("Set-ID regular files: 11", rendered)
        self.assertNotIn("ordinary-suid", rendered)

    def test_filesystem_details_lists_benign_setid_inventory(self) -> None:
        item = SetIdFile(
            FileMetadata(
                "/usr/bin/ordinary-suid", 0, 0, 0o4755, 4096, "regular file"
            ),
            True,
            ("rw",),
        )
        coverage = FilesystemCoverage(
            (item,), CoverageStatus.COLLECTED, ("/usr",), 40, 0.02
        )
        output = io.StringIO()

        with (
            patch.object(app, "collect_sensitive_file_metadata", return_value=()),
            patch.object(app, "collect_setid_files", return_value=coverage),
            patch.object(app, "terminal_size", return_value=(120, 40)),
            contextlib.redirect_stdout(output),
        ):
            app._dispatch_command("scan filesystem --details")

        rendered = " ".join(output.getvalue().split())
        self.assertIn("/usr/bin/ordinary-suid", rendered)
        self.assertIn("mode 4755", rendered)
        self.assertIn("ELF: yes", rendered)
        self.assertIn("mount options: rw", rendered)
        self.assertIn("Set-ID verified findings: 0", rendered)
        self.assertNotIn("FS-SETID-WORLD-WRITE-001", rendered)


    def test_full_scan_includes_setid_finding_in_central_report(self) -> None:
        item = SetIdFile(
            FileMetadata("/usr/local/bin/writable", 0, 0, 0o4713, 99, "regular file"),
            True,
            ("rw",),
        )
        coverage = FilesystemCoverage((item,), CoverageStatus.COLLECTED, ("/usr",), 4, 0.02)
        output = io.StringIO()
        with (
            patch_supplementary_collectors(app),
            patch.object(host_area, "collect_system_info", return_value=SystemInfo()),
            patch.object(app, "collect_local_users", return_value=()),
            patch.object(app, "collect_sudo_privileges", return_value=()),
            patch.object(app, "collect_sensitive_file_metadata", return_value=()),
            patch.object(app, "collect_setid_files", return_value=coverage),
            patch.object(app, "collect_services", return_value=()),
            patch.object(ssh_area, "collect_ssh_config", return_value=SSHConfig("no", False, False, True)),
            patch.object(app, "terminal_size", return_value=(100, 30)),
            contextlib.redirect_stdout(output),
        ):
            app._show_scan(detailed=True)
        rendered = output.getvalue()
        self.assertIn("✗ ISSUES DETECTED", rendered)
        self.assertIn("⚠ FAIL · Active set-ID ELF file is world-writable", rendered)
        self.assertIn("FS-SETID-WORLD-WRITE-001", rendered)
        self.assertIn("mode: 4713", rendered)


if __name__ == "__main__":
    unittest.main()
