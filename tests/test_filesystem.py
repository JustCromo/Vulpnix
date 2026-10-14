"""Deterministic tests for sensitive filesystem metadata assessment."""

import contextlib
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix_test_support import patch_supplementary_collectors
from vulpnix.collectors import filesystem
from vulpnix.collectors.filesystem import collect_sensitive_file_metadata
from vulpnix.models import (
    FileMetadata,
    FileMetadataResult,
    FileMetadataStatus,
    CoverageStatus,
    FilesystemCoverage,
    SSHConfig,
    SystemInfo,
)
from vulpnix.parsers.filesystem import normalize_file_metadata
from vulpnix.rules.filesystem import assess_sensitive_files


def result(
    path: str,
    mode: int = 0o644,
    *,
    uid: int = 0,
    gid: int = 0,
    file_type: str = "regular file",
    status: FileMetadataStatus = FileMetadataStatus.COLLECTED,
    reason: str | None = None,
) -> FileMetadataResult:
    metadata = None
    if status is FileMetadataStatus.COLLECTED:
        metadata = FileMetadata(path, uid, gid, mode, 128, file_type)
    return FileMetadataResult(path, status, metadata, reason)


def empty_coverage() -> FilesystemCoverage:
    return FilesystemCoverage((), CoverageStatus.COLLECTED, (), 0, 0.0)


class FilesystemNormalizationTests(unittest.TestCase):
    def test_normalizes_regular_file_and_numeric_owner_metadata(self) -> None:
        raw = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o640,
            st_uid=123,
            st_gid=456,
            st_size=90,
        )
        metadata = normalize_file_metadata("/etc/passwd", raw)
        self.assertEqual(metadata.uid, 123)
        self.assertEqual(metadata.gid, 456)
        self.assertEqual(metadata.mode, 0o640)
        self.assertEqual(metadata.size, 90)
        self.assertEqual(metadata.type, "regular file")

    def test_normalizes_directory_symlink_and_other_types(self) -> None:
        for raw_type, expected in (
            (stat.S_IFDIR, "directory"),
            (stat.S_IFLNK, "symlink"),
            (stat.S_IFIFO, "other"),
        ):
            raw = SimpleNamespace(
                st_mode=raw_type | 0o777,
                st_uid=0,
                st_gid=0,
                st_size=0,
            )
            self.assertEqual(normalize_file_metadata("/etc/passwd", raw).type, expected)

    def test_rejects_malformed_or_inconsistent_metadata(self) -> None:
        for field, value in (("st_uid", -1), ("st_gid", -1), ("st_size", -1), ("st_mode", -1)):
            raw = {
                "st_mode": stat.S_IFREG | 0o644,
                "st_uid": 0,
                "st_gid": 0,
                "st_size": 10,
            }
            raw[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                normalize_file_metadata("/etc/passwd", SimpleNamespace(**raw))

    def test_incomplete_metadata_is_rejected_without_assessment_finding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("passwd", "shadow", "group", "gshadow"):
                (root / name).touch()

            def incomplete_stat(path: str, **_kwargs: object) -> SimpleNamespace:
                if path == "passwd":
                    return SimpleNamespace(
                        st_mode=stat.S_IFREG | 0o644,
                        st_gid=0,
                        st_size=12,
                    )
                raise FileNotFoundError(path)

            with (
                patch.object(filesystem, "_ETC_DIRECTORY", directory),
                patch.object(filesystem, "_read_id_map", return_value=((0, 65536),)),
                patch.object(filesystem, "_read_overflow_id", return_value=65534),
                patch.object(filesystem.os, "stat", side_effect=incomplete_stat),
            ):
                collected = collect_sensitive_file_metadata()

        passwd_result = collected[0]
        self.assertEqual(Path(passwd_result.path).name, "passwd")
        self.assertEqual(passwd_result.status, FileMetadataStatus.NOT_ASSESSED)
        self.assertIn("Incomplete filesystem metadata", passwd_result.reason)
        assessment = assess_sensitive_files(
            (
                FileMetadataResult(
                    "/etc/passwd",
                    passwd_result.status,
                    reason=passwd_result.reason,
                ),
            )
        )
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.review[0].path, "/etc/passwd")


class SensitiveFileCollectorTests(unittest.TestCase):
    def test_collects_only_fixed_entries_and_does_not_follow_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("passwd", "shadow", "group", "gshadow"):
                (root / name).write_text("ignored contents", encoding="utf-8")
                (root / name).chmod(0o640)
            (root / "shadow").unlink()
            (root / "shadow").symlink_to(root / "passwd")
            with patch.object(filesystem, "_ETC_DIRECTORY", directory):
                collected = collect_sensitive_file_metadata()

        by_path = {item.path.rsplit("/", 1)[-1]: item for item in collected}
        self.assertEqual(set(by_path), {"passwd", "shadow", "group", "gshadow"})
        self.assertEqual(by_path["passwd"].metadata.type, "regular file")
        self.assertEqual(by_path["passwd"].metadata.mode, 0o640)
        self.assertEqual(by_path["shadow"].metadata.type, "symlink")

    def test_missing_and_inaccessible_files_remain_not_assessed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("passwd", "group", "gshadow"):
                (root / name).touch()

            original_stat = os.stat

            def controlled_stat(path: str, **kwargs: object) -> os.stat_result:
                if path == "group":
                    raise PermissionError("denied")
                return original_stat(path, **kwargs)

            with (
                patch.object(filesystem, "_ETC_DIRECTORY", directory),
                patch.object(filesystem.os, "stat", side_effect=controlled_stat),
            ):
                collected = collect_sensitive_file_metadata()

        by_name = {item.path.rsplit("/", 1)[-1]: item for item in collected}
        self.assertEqual(by_name["shadow"].status, FileMetadataStatus.NOT_ASSESSED)
        self.assertIn("missing", by_name["shadow"].reason)
        self.assertEqual(by_name["group"].status, FileMetadataStatus.NOT_ASSESSED)
        self.assertIn("permission denied", by_name["group"].reason)

    def test_unmapped_owner_ids_are_not_represented_as_real_ids(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("passwd", "shadow", "group", "gshadow"):
                (root / name).touch()
            with (
                patch.object(filesystem, "_ETC_DIRECTORY", directory),
                patch.object(filesystem, "_read_id_map", return_value=((1, 1),)),
                patch.object(filesystem, "_read_overflow_id", return_value=65534),
            ):
                collected = collect_sensitive_file_metadata()

        self.assertTrue(all(item.metadata.uid is None for item in collected))
        self.assertTrue(all(item.metadata.gid is None for item in collected))
        self.assertTrue(all(item.status is FileMetadataStatus.PARTIAL for item in collected))
        self.assertTrue(all("owner IDs are not mapped" in item.reason for item in collected))


class SensitiveFileRuleTests(unittest.TestCase):
    def test_non_root_owner_and_group_or_other_write_create_findings(self) -> None:
        assessment = assess_sensitive_files(
            (
                result("/etc/passwd", 0o664, uid=1000, gid=17),
                result("/etc/group", 0o666),
            )
        )
        self.assertEqual(len(assessment.findings), 3)
        evidence = "\n".join(item.evidence for item in assessment.findings)
        for detail in ("/etc/passwd", "UID: 1000", "GID: 17", "mode: 0664", "/etc/group", "mode: 0666"):
            self.assertIn(detail, evidence)

    def test_world_write_only_creates_finding_without_group_write(self) -> None:
        assessment = assess_sensitive_files((result("/etc/passwd", 0o602),))
        self.assertEqual(len(assessment.findings), 1)
        finding = assessment.findings[0]
        self.assertEqual(finding.rule_id, "FS-SENSITIVE-WRITE-001")
        self.assertIn("mode: 0602", finding.evidence)
        self.assertEqual(0o602 & 0o020, 0)
        self.assertNotEqual(0o602 & 0o002, 0)

    def test_shadow_and_gshadow_world_read_create_findings(self) -> None:
        assessment = assess_sensitive_files(
            (result("/etc/shadow", 0o604), result("/etc/gshadow", 0o604))
        )
        self.assertEqual(len(assessment.findings), 2)
        self.assertTrue(all(item.rule_id == "FS-SECRET-WORLD-READ-001" for item in assessment.findings))

    def test_group_read_shadow_is_review_and_not_a_finding(self) -> None:
        assessment = assess_sensitive_files((result("/etc/shadow", 0o640, gid=42),))
        self.assertEqual(assessment.findings, ())
        self.assertIn("group-readable", assessment.review[0].reason)

    def test_passwd_group_readability_and_nonstandard_gid_are_not_findings(self) -> None:
        assessment = assess_sensitive_files(
            (result("/etc/passwd", 0o644, gid=55), result("/etc/group", 0o644, gid=77))
        )
        self.assertEqual(assessment.findings, ())

    def test_unmapped_owner_ids_do_not_create_owner_finding(self) -> None:
        metadata = FileMetadata("/etc/passwd", None, None, 0o644, 10, "regular file")
        assessment = assess_sensitive_files(
            (FileMetadataResult("/etc/passwd", FileMetadataStatus.COLLECTED, metadata),)
        )
        self.assertEqual(assessment.findings, ())
        self.assertEqual(len(assessment.review), 2)

    def test_missing_symlink_directory_and_other_type_are_review_only(self) -> None:
        assessment = assess_sensitive_files(
            (
                result("/etc/passwd", status=FileMetadataStatus.NOT_ASSESSED, reason="target is missing"),
                result("/etc/shadow", file_type="symlink"),
                result("/etc/group", file_type="directory"),
                result("/etc/gshadow", file_type="other"),
            )
        )
        self.assertEqual(assessment.findings, ())
        self.assertEqual(len(assessment.review), 4)
        self.assertEqual(len(assessment.checked), 0)

    def test_inconsistent_or_out_of_scope_metadata_is_review_only(self) -> None:
        inconsistent = FileMetadata("/etc/group", 0, 0, 0o666, 1, "regular file")
        assessment = assess_sensitive_files(
            (
                FileMetadataResult(
                    "/etc/passwd", FileMetadataStatus.COLLECTED, inconsistent
                ),
                result("/tmp/other", 0o666),
            )
        )
        self.assertEqual(assessment.findings, ())
        self.assertEqual(len(assessment.review), 2)


class FilesystemCLITests(unittest.TestCase):
    def test_scan_filesystem_command_renders_concise_assessment(self) -> None:
        output = io.StringIO()
        records = (
            FileMetadataResult(
                "/etc/passwd",
                FileMetadataStatus.PARTIAL,
                FileMetadata("/etc/passwd", None, None, 0o644, 128, "regular file"),
                "owner IDs are not mapped in the current user namespace",
            ),
            result("/etc/shadow", 0o640, gid=42),
            result("/etc/group"),
            result("/etc/gshadow", status=FileMetadataStatus.NOT_ASSESSED, reason="permission denied"),
        )
        with (
            patch.object(app, "collect_sensitive_file_metadata", return_value=records),
            patch.object(app, "collect_setid_files", return_value=empty_coverage()),
            patch.object(app, "terminal_size", return_value=(80, 24)),
            contextlib.redirect_stdout(output),
        ):
            self.assertTrue(app._dispatch_command("scan filesystem"))

        rendered = output.getvalue()
        self.assertIn("FILESYSTEM", rendered)
        self.assertIn("FACTS", rendered)
        self.assertIn("ASSESSMENT", rendered)
        self.assertIn("REVIEW", rendered)
        self.assertIn("DETAILS", rendered)
        self.assertIn("/etc/shadow", rendered)
        self.assertIn("/etc/gshadow", rendered)
        self.assertIn("owner UID is not mapped", rendered)
        self.assertIn("NOT_ASSESSED", rendered)
        self.assertNotIn("[FAIL]", rendered)
        self.assertNotIn("ignored contents", rendered)

    def test_scan_filesystem_details_lists_sensitive_files_when_all_pass(self) -> None:
        output = io.StringIO()
        records = (
            result("/etc/passwd", 0o644),
            result("/etc/shadow", 0o600),
            result("/etc/group", 0o644),
            result("/etc/gshadow", 0o600),
        )

        with (
            patch.object(app, "collect_sensitive_file_metadata", return_value=records),
            patch.object(app, "collect_setid_files", return_value=empty_coverage()),
            patch.object(app, "terminal_size", return_value=(120, 40)),
            contextlib.redirect_stdout(output),
        ):
            app._dispatch_command("scan filesystem --details")

        rendered = output.getvalue()
        for file_path in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"):
            with self.subTest(path=file_path):
                self.assertIn(file_path, rendered)

        self.assertIn("0644", rendered)
        self.assertIn("0600", rendered)
        self.assertIn("No defined insecure condition detected", rendered)


    def test_help_and_completion_include_filesystem_scan(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app._show_help()
        self.assertIn("scan filesystem", output.getvalue())
        self.assertIn("scan filesystem", app._command_completions("scan f"))

    def test_full_scan_includes_filesystem_section_and_findings(self) -> None:
        output = io.StringIO()
        records = (result("/etc/passwd", 0o664),)
        with (
            patch_supplementary_collectors(app),
            patch.object(app, "collect_system_info", return_value=SystemInfo()),
            patch.object(app, "collect_local_users", return_value=()),
            patch.object(app, "collect_sudo_privileges", return_value=()),
            patch.object(app, "collect_sensitive_file_metadata", return_value=records),
            patch.object(app, "collect_setid_files", return_value=empty_coverage()),
            patch.object(app, "collect_services", return_value=()),
            patch.object(app, "collect_ssh_config", return_value=SSHConfig("no", False, False, True)),
            contextlib.redirect_stdout(output),
        ):
            app._show_scan()

        rendered = output.getvalue()
        self.assertIn("FILESYSTEM", rendered)
        self.assertIn("FS-SENSITIVE-WRITE-001", rendered)
        self.assertIn("/etc/passwd", rendered)


if __name__ == "__main__":
    unittest.main()
