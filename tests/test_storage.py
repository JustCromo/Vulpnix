"""Tests for mount metadata, capacity collection, and storage rules."""

import unittest
from types import SimpleNamespace

from vulpnix.collectors.storage import collect_storage_snapshot
from vulpnix.findings import FindingStatus
from vulpnix.models.storage import (
    MountedFilesystem,
    StorageSnapshot,
    StorageStatus,
)
from vulpnix.parsers.mountinfo import parse_mountinfo
from vulpnix.rules.storage import assess_storage


def mountinfo(
    mount_point="/",
    *,
    fs_type="ext4",
    source="/dev/test",
    options="rw,relatime",
    super_options="rw,errors=remount-ro",
):
    return (
        f"31 22 8:1 / {mount_point} {options} "
        f"- {fs_type} {source} {super_options}\n"
    )


def fake_statvfs(
    *,
    blocks=100,
    free_blocks=40,
    available_blocks=30,
    files=1000,
    free_files=400,
    available_files=300,
    block_size=4096,
):
    return SimpleNamespace(
        f_bsize=block_size,
        f_frsize=block_size,
        f_blocks=blocks,
        f_bfree=free_blocks,
        f_bavail=available_blocks,
        f_files=files,
        f_ffree=free_files,
        f_favail=available_files,
    )


def filesystem(
    mount_point="/",
    *,
    total_bytes=100 * 4096,
    available_bytes=50 * 4096,
    total_inodes=1000,
    available_inodes=500,
    options=("rw",),
    status=StorageStatus.COLLECTED,
):
    return MountedFilesystem(
        mount_point=mount_point,
        fs_type="ext4",
        source="/dev/test",
        mount_options=tuple(options),
        super_options=("rw",),
        total_bytes=total_bytes,
        free_bytes=available_bytes,
        available_bytes=available_bytes,
        total_inodes=total_inodes,
        free_inodes=available_inodes,
        available_inodes=available_inodes,
        status=status,
    )


class MountInfoMetadataTests(unittest.TestCase):
    def test_parser_preserves_existing_fields_and_adds_metadata(self):
        parsed = parse_mountinfo(
            "31 22 8:1 / /opt/tools\\040area rw,nosuid "
            "- ext4 /dev/disk\\040one rw,errors=remount-ro\n"
        )
        item = parsed[0]
        self.assertEqual(item.mount_point, "/opt/tools area")
        self.assertIn("nosuid", item.options)
        self.assertEqual(item.fs_type, "ext4")
        self.assertEqual(item.source, "/dev/disk one")
        self.assertEqual(item.root, "/")
        self.assertEqual(item.device_id, "8:1")
        self.assertIn("errors=remount-ro", item.super_options)

    def test_parser_still_supports_two_argument_mount_info_construction(self):
        from vulpnix.parsers.mountinfo import MountInfo

        item = MountInfo("/", frozenset({"rw"}))
        self.assertEqual(item.mount_point, "/")
        self.assertIsNone(item.fs_type)
        self.assertEqual(item.super_options, frozenset())


class StorageCollectorTests(unittest.TestCase):
    def test_collects_capacity_inode_and_mount_metadata(self):
        result = collect_storage_snapshot(
            mountinfo_text=mountinfo("/"),
            statvfs_fn=lambda path: fake_statvfs(),
        )

        self.assertEqual(result.status, StorageStatus.COLLECTED)
        self.assertEqual(len(result.filesystems), 1)
        item = result.filesystems[0]
        self.assertEqual(item.fs_type, "ext4")
        self.assertEqual(item.source, "/dev/test")
        self.assertEqual(item.total_bytes, 100 * 4096)
        self.assertEqual(item.free_bytes, 40 * 4096)
        self.assertEqual(item.available_bytes, 30 * 4096)
        self.assertEqual(item.total_inodes, 1000)
        self.assertEqual(item.available_inodes, 300)
        self.assertIn("rw", item.mount_options)

    def test_statvfs_failure_is_not_assessed(self):
        def denied(_path):
            raise PermissionError("access denied")

        result = collect_storage_snapshot(
            mountinfo_text=mountinfo("/"),
            statvfs_fn=denied,
        )
        self.assertEqual(result.status, StorageStatus.PARTIAL)
        self.assertEqual(result.filesystems[0].status, StorageStatus.NOT_ASSESSED)
        self.assertIsNone(result.filesystems[0].total_bytes)
        self.assertTrue(result.messages)

    def test_unreadable_or_invalid_mount_inventory_is_not_assessed(self):
        result = collect_storage_snapshot(mountinfo_text="invalid input\n")
        self.assertEqual(result.status, StorageStatus.NOT_ASSESSED)
        self.assertEqual(result.filesystems, ())

    def test_mount_limit_is_visible_as_partial_coverage(self):
        data = mountinfo("/") + mountinfo("/boot")
        result = collect_storage_snapshot(
            mountinfo_text=data,
            max_mounts=1,
            statvfs_fn=lambda path: fake_statvfs(),
        )
        self.assertEqual(result.status, StorageStatus.PARTIAL)
        self.assertEqual(len(result.filesystems), 1)
        self.assertIn("limited", result.messages[0])

    def test_missing_inode_counters_do_not_turn_into_zero(self):
        result = collect_storage_snapshot(
            mountinfo_text=mountinfo("/"),
            statvfs_fn=lambda path: fake_statvfs(
                files=0,
                free_files=0,
                available_files=0,
            ),
        )
        item = result.filesystems[0]
        self.assertIsNone(item.total_inodes)
        self.assertIsNone(item.available_inodes)


class StorageRuleTests(unittest.TestCase):
    def test_low_space_and_inode_capacity_require_review(self):
        fs = filesystem(
            total_bytes=10000,
            available_bytes=400,
            total_inodes=1000,
            available_inodes=20,
        )
        findings = assess_storage(
            StorageSnapshot((fs,), StorageStatus.COLLECTED)
        )
        self.assertEqual(len(findings), 2)
        self.assertTrue(
            all(item.status is FindingStatus.REVIEW for item in findings)
        )
        self.assertTrue(any("storage" in item.title.lower() for item in findings))
        self.assertTrue(any("inode" in item.title.lower() for item in findings))

    def test_healthy_filesystem_creates_no_findings(self):
        fs = filesystem()
        findings = assess_storage(
            StorageSnapshot((fs,), StorageStatus.COLLECTED)
        )
        self.assertEqual(findings, ())

    def test_zero_or_unavailable_counters_are_not_assessed_as_full(self):
        fs = filesystem(
            total_bytes=None,
            available_bytes=None,
            total_inodes=None,
            available_inodes=None,
        )
        findings = assess_storage(
            StorageSnapshot((fs,), StorageStatus.COLLECTED)
        )
        self.assertEqual(findings, ())

    def test_dedicated_temporary_mount_without_common_flags_needs_review(self):
        fs = filesystem("/tmp", options=("rw",))
        findings = assess_storage(
            StorageSnapshot((fs,), StorageStatus.COLLECTED)
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, FindingStatus.REVIEW)
        self.assertIn("nosuid", findings[0].evidence)
        self.assertIn("nodev", findings[0].evidence)

    def test_dedicated_temporary_mount_with_common_flags_passes_rule(self):
        fs = filesystem("/tmp", options=("rw", "nosuid", "nodev"))
        findings = assess_storage(
            StorageSnapshot((fs,), StorageStatus.COLLECTED)
        )
        self.assertEqual(findings, ())

    def test_root_mount_does_not_get_temporary_mount_rule(self):
        fs = filesystem("/", options=("rw",))
        findings = assess_storage(
            StorageSnapshot((fs,), StorageStatus.COLLECTED)
        )
        self.assertEqual(findings, ())

    def test_incomplete_snapshot_does_not_produce_findings_from_missing_data(self):
        fs = filesystem(status=StorageStatus.NOT_ASSESSED)
        findings = assess_storage(
            StorageSnapshot((fs,), StorageStatus.NOT_ASSESSED)
        )
        self.assertEqual(findings, ())

    def test_invalid_thresholds_are_rejected(self):
        snapshot = StorageSnapshot((), StorageStatus.COLLECTED)
        with self.assertRaises(ValueError):
            assess_storage(snapshot, low_space_percent=0)
        with self.assertRaises(ValueError):
            assess_storage(
                snapshot,
                low_space_percent=2,
                critical_space_percent=5,
            )


if __name__ == "__main__":
    unittest.main()
