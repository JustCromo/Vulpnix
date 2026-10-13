import unittest
from pathlib import Path
from unittest.mock import patch

from vulpnix.collectors import host


class HostCollectorTests(unittest.TestCase):
    def test_collects_linux_host_facts_and_uptime(self):
        with (
            patch.object(host.platform, "system", return_value="Linux"),
            patch.object(
                host.platform,
                "freedesktop_os_release",
                return_value={"PRETTY_NAME": "Example Linux", "VERSION_ID": "1"},
            ),
            patch.object(host.platform, "node", return_value="example-host"),
            patch.object(host.platform, "release", return_value="6.8.1"),
            patch.object(host.platform, "machine", return_value="x86_64"),
            patch.object(Path, "read_text", return_value="123.5 0.0"),
        ):
            info = host.collect_system_info()

        self.assertEqual(info.hostname, "example-host")
        self.assertEqual(info.distribution, "Example Linux")
        self.assertEqual(info.distribution_version, "1")
        self.assertEqual(info.kernel_release, "6.8.1")
        self.assertEqual(info.architecture, "x86_64")
        self.assertEqual(info.uptime_seconds, 123.5)

    def test_uses_distribution_name_when_pretty_name_is_missing(self):
        with (
            patch.object(host.platform, "system", return_value="Linux"),
            patch.object(
                host.platform,
                "freedesktop_os_release",
                return_value={"NAME": "Example Linux", "VERSION_ID": "2"},
            ),
            patch.object(host.platform, "node", return_value="host"),
            patch.object(host.platform, "release", return_value="kernel"),
            patch.object(host.platform, "machine", return_value="x86_64"),
            patch.object(Path, "read_text", return_value="10.0 0.0"),
        ):
            info = host.collect_system_info()

        self.assertEqual(info.distribution, "Example Linux")
        self.assertEqual(info.distribution_version, "2")

    def test_missing_os_release_and_unreadable_uptime_remain_unknown(self):
        with (
            patch.object(host.platform, "system", return_value="Linux"),
            patch.object(
                host.platform,
                "freedesktop_os_release",
                side_effect=OSError("unavailable"),
            ),
            patch.object(host.platform, "node", return_value="host"),
            patch.object(host.platform, "release", return_value="kernel"),
            patch.object(host.platform, "machine", return_value="x86_64"),
            patch.object(Path, "read_text", side_effect=PermissionError("denied")),
        ):
            info = host.collect_system_info()

        self.assertIsNone(info.distribution)
        self.assertIsNone(info.distribution_version)
        self.assertIsNone(info.uptime_seconds)

    def test_rejects_non_linux_systems(self):
        with patch.object(host.platform, "system", return_value="Darwin"):
            with self.assertRaises(NotImplementedError):
                host.collect_system_info()

    def test_invalid_uptime_values_are_not_accepted(self):
        for value in ("invalid", "nan", "inf", "-1"):
            with self.subTest(value=value):
                with patch.object(Path, "read_text", return_value=f"{value} 0.0"):
                    self.assertIsNone(host._read_uptime_seconds())


if __name__ == "__main__":
    unittest.main()
