"""Tests for metadata-only SSH host private-key assessment."""

import os
from pathlib import Path
import tempfile
import unittest

from vulpnix.collectors.ssh_keys import collect_ssh_host_key_metadata
from vulpnix.findings import FindingStatus
from vulpnix.models import SSHHostKeyObservation
from vulpnix.rules.ssh_keys import assess_ssh_host_key_metadata


class SSHHostKeyCollectorTests(unittest.TestCase):
    def test_collects_metadata_without_reading_key_contents(self):
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "ssh_host_ed25519_key"
            key.write_text("NEVER READ THIS KEY MATERIAL", encoding="utf-8")
            key.chmod(0o600)
            observations = collect_ssh_host_key_metadata(temp)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].path, str(key))
        self.assertEqual(observations[0].mode, 0o600)
        self.assertTrue(observations[0].is_regular)
        self.assertFalse(observations[0].is_symlink)

    def test_does_not_follow_key_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "real_key"
            target.write_text("key", encoding="utf-8")
            (Path(temp) / "ssh_host_rsa_key").symlink_to(target)
            observations = collect_ssh_host_key_metadata(temp)
        self.assertEqual(len(observations), 1)
        self.assertTrue(observations[0].is_symlink)
        self.assertFalse(observations[0].is_regular)


class SSHHostKeyRulesTests(unittest.TestCase):
    def test_secure_key_metadata_passes(self):
        assessment = assess_ssh_host_key_metadata((SSHHostKeyObservation("/etc/ssh/key", 0, 0o600, True, False),))
        self.assertEqual(assessment.checks[0].status, FindingStatus.PASS)
        self.assertEqual(assessment.findings, ())

    def test_group_readable_or_non_root_owned_key_is_fail(self):
        assessment = assess_ssh_host_key_metadata((SSHHostKeyObservation("/etc/ssh/key", 1000, 0o640, True, False),))
        self.assertEqual(assessment.checks[0].status, FindingStatus.FAIL)
        self.assertEqual(assessment.findings[0].status, FindingStatus.FAIL)

    def test_missing_owner_or_mode_is_not_assessed_not_failed(self):
        assessment = assess_ssh_host_key_metadata((
            SSHHostKeyObservation("/etc/ssh/key-a", None, 0o600, True, False),
            SSHHostKeyObservation("/etc/ssh/key-b", 0, None, True, False),
        ))
        self.assertEqual([check.status for check in assessment.checks], [FindingStatus.NOT_ASSESSED, FindingStatus.NOT_ASSESSED])
        self.assertFalse(any(item.status is FindingStatus.FAIL for item in assessment.findings))

    def test_unavailable_and_symlink_metadata_are_not_false_failures(self):
        assessment = assess_ssh_host_key_metadata((
            SSHHostKeyObservation("/etc/ssh/key", None, None, None, False, "permission denied"),
            SSHHostKeyObservation("/etc/ssh/link", 0, 0o777, False, True),
        ))
        self.assertEqual(assessment.checks[0].status, FindingStatus.NOT_ASSESSED)
        self.assertEqual(assessment.checks[1].status, FindingStatus.REVIEW)
        self.assertFalse(any(item.status is FindingStatus.FAIL for item in assessment.findings))
