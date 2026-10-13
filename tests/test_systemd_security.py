"""Tests for systemd unit-fragment metadata parsing and assessment."""

import subprocess
import unittest
from unittest.mock import patch

from vulpnix.collectors.systemd_security import (
    _allowed_unit_path,
    _parse_show_output,
    collect_service_unit_file_metadata,
)
from vulpnix.models import Service, UnitFileObservation
from vulpnix.findings import FindingStatus
from vulpnix.models import UnitFileObservation
from vulpnix.rules.systemd_security import assess_systemd_unit_metadata


class SystemdUnitOutputTests(unittest.TestCase):
    def test_parses_fragments_and_dropins_for_multiple_units(self):
        output = (
            "Id=ssh.service\nFragmentPath=/usr/lib/systemd/system/ssh.service\nDropInPaths=\n\n"
            "Id=demo.service\nFragmentPath=/etc/systemd/system/demo.service\n"
            "DropInPaths=/etc/systemd/system/demo.service.d/override.conf\n"
        )
        records = _parse_show_output(output)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0][0], "ssh.service")
        self.assertEqual(records[1][2], ("/etc/systemd/system/demo.service.d/override.conf",))

    def test_rejects_paths_outside_systemd_roots_and_parent_traversal(self):
        self.assertTrue(_allowed_unit_path("/usr/lib/systemd/system/ssh.service"))
        self.assertFalse(_allowed_unit_path("/etc/passwd"))
        self.assertFalse(_allowed_unit_path("/etc/systemd/system/../../shadow"))
        self.assertFalse(_allowed_unit_path("relative.service"))


    def test_accepts_standard_systemd_system_unit_load_paths(self):
        paths = (
            "/etc/systemd/system.control/demo.service",
            "/run/systemd/system.control/demo.service",
            "/run/systemd/transient/demo.service",
            "/run/systemd/generator.early/demo.service",
            "/etc/systemd/system.attached/demo.service",
            "/run/systemd/system/demo.service",
            "/run/systemd/system.attached/demo.service",
            "/run/systemd/generator/demo.service",
            "/usr/local/lib/systemd/system/demo.service",
            "/usr/lib/systemd/system/demo.service",
            "/lib/systemd/system/demo.service",
            "/run/systemd/generator.late/demo.service",
        )

        for file_path in paths:
            with self.subTest(path=file_path):
                self.assertTrue(_allowed_unit_path(file_path))


class SystemdUnitCollectorTests(unittest.TestCase):
    def test_invalid_template_does_not_block_other_unit_metadata(self):
        output = (
            "Id=demo.service\n"
            "FragmentPath=/usr/lib/systemd/system/demo.service\n"
            "DropInPaths=\n"
        )
        with (
            patch(
                "vulpnix.collectors.systemd_security.shutil.which",
                return_value="/usr/bin/systemctl",
            ),
            patch(
                "vulpnix.collectors.systemd_security.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["/usr/bin/systemctl"],
                    returncode=0,
                    stdout=output,
                    stderr="",
                ),
            ) as run,
            patch(
                "vulpnix.collectors.systemd_security._inspect_path",
                return_value=UnitFileObservation(
                    "demo.service",
                    "/usr/lib/systemd/system/demo.service",
                    0,
                    0o644,
                    True,
                    False,
                ),
            ),
        ):
            observations, review = collect_service_unit_file_metadata((
                Service(name="alsa-card-wait@.service"),
                Service(name="demo.service"),
            ))

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].unit, "demo.service")
        self.assertTrue(any("alsa-card-wait@.service" in item for item in review))
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0]
        self.assertIn("demo.service", command)
        self.assertNotIn("alsa-card-wait@.service", command)


    def test_alias_name_is_matched_to_returned_canonical_unit(self):
        output = (
            "Id=sddm.service\n"
            "Names=sddm.service display-manager.service\n"
            "LoadState=loaded\n"
            "FragmentPath=/usr/lib/systemd/system/sddm.service\n"
            "DropInPaths=\n"
            "UnitFileState=enabled\n"
        )

        with (
            patch(
                "vulpnix.collectors.systemd_security.shutil.which",
                return_value="/usr/bin/systemctl",
            ),
            patch(
                "vulpnix.collectors.systemd_security.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["/usr/bin/systemctl"],
                    returncode=0,
                    stdout=output,
                    stderr="",
                ),
            ),
            patch(
                "vulpnix.collectors.systemd_security._inspect_path",
                return_value=UnitFileObservation(
                    "sddm.service",
                    "/usr/lib/systemd/system/sddm.service",
                    0,
                    0o644,
                    True,
                    False,
                ),
            ),
        ):
            observations, review = collect_service_unit_file_metadata((
                Service(name="display-manager.service"),
            ))

        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0].unit, "sddm.service")
        self.assertFalse(
            any("no fragment metadata" in item.lower() for item in review)
        )


    def test_not_found_and_missing_fragment_units_are_explicitly_unassessed(self):
        output = (
            "Id=missing.service\n"
            "Names=missing.service\n"
            "LoadState=not-found\n"
            "FragmentPath=\n"
            "DropInPaths=\n"
            "UnitFileState=\n\n"
            "Id=no-fragment.service\n"
            "Names=no-fragment.service\n"
            "LoadState=loaded\n"
            "FragmentPath=\n"
            "DropInPaths=\n"
            "UnitFileState=static\n"
        )

        with (
            patch(
                "vulpnix.collectors.systemd_security.shutil.which",
                return_value="/usr/bin/systemctl",
            ),
            patch(
                "vulpnix.collectors.systemd_security.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["/usr/bin/systemctl"],
                    returncode=0,
                    stdout=output,
                    stderr="",
                ),
            ) as run,
            patch(
                "vulpnix.collectors.systemd_security._inspect_path",
            ) as inspect,
        ):
            observations, review = collect_service_unit_file_metadata((
                Service(name="missing.service"),
                Service(name="no-fragment.service"),
            ))

        self.assertEqual(observations, ())
        self.assertTrue(any(
            "missing.service was not found by systemd" in item
            for item in review
        ))
        self.assertTrue(any(
            "no-fragment.service has no FragmentPath" in item
            for item in review
        ))
        self.assertFalse(any("no unit record" in item for item in review))
        inspect.assert_not_called()

        command = run.call_args.args[0]
        properties = next(arg for arg in command if arg.startswith("--property="))
        self.assertIn("Names", properties)
        self.assertIn("LoadState", properties)


    def test_masked_runtime_unit_is_reported_without_inspecting_its_fragment(self):
        output = (
            "Id=masked.service\n"
            "FragmentPath=/run/systemd/generator/masked.service\n"
            "DropInPaths=\n"
            "UnitFileState=masked-runtime\n\n"
            "Id=demo.service\n"
            "FragmentPath=/usr/lib/systemd/system/demo.service\n"
            "DropInPaths=\n"
            "UnitFileState=enabled\n"
        )

        def inspect_path(unit, file_path):
            if unit == "masked.service":
                return UnitFileObservation(
                    unit, file_path, None, None, None, True,
                    "path was outside approved systemd unit directories",
                )
            return UnitFileObservation(
                unit, file_path, 0, 0o644, True, False
            )

        with (
            patch(
                "vulpnix.collectors.systemd_security.shutil.which",
                return_value="/usr/bin/systemctl",
            ),
            patch(
                "vulpnix.collectors.systemd_security.subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["/usr/bin/systemctl"],
                    returncode=0,
                    stdout=output,
                    stderr="",
                ),
            ) as run,
            patch(
                "vulpnix.collectors.systemd_security._inspect_path",
                side_effect=inspect_path,
            ) as inspect,
        ):
            observations, review = collect_service_unit_file_metadata((
                Service(name="masked.service"),
                Service(name="demo.service"),
            ))

        self.assertEqual(tuple(item.unit for item in observations), ("demo.service",))
        self.assertTrue(
            any("masked.service" in item and "masked-runtime" in item for item in review)
        )
        self.assertEqual(inspect.call_count, 1)
        command = run.call_args.args[0]
        self.assertIn("UnitFileState", next(
            arg for arg in command if arg.startswith("--property=")
        ))


class SystemdUnitRulesTests(unittest.TestCase):
    def test_safe_root_owned_not_group_writable_file_passes(self):
        assessment = assess_systemd_unit_metadata((UnitFileObservation("demo.service", "/etc/systemd/system/demo.service", 0, 0o644, True, False),))
        self.assertEqual(assessment.checks[0].status, FindingStatus.PASS)
        self.assertEqual(assessment.findings, ())

    def test_non_root_owned_or_group_writable_unit_is_fail(self):
        assessment = assess_systemd_unit_metadata((UnitFileObservation("demo.service", "/etc/systemd/system/demo.service", 1000, 0o664, True, False),))
        self.assertEqual(assessment.checks[0].status, FindingStatus.FAIL)
        self.assertEqual(assessment.findings[0].status, FindingStatus.FAIL)

    def test_missing_owner_or_mode_is_not_assessed_not_failed(self):
        assessment = assess_systemd_unit_metadata((
            UnitFileObservation("a.service", "/etc/systemd/system/a.service", None, 0o644, True, False),
            UnitFileObservation("b.service", "/etc/systemd/system/b.service", 0, None, True, False),
        ))
        self.assertEqual([check.status for check in assessment.checks], [FindingStatus.NOT_ASSESSED, FindingStatus.NOT_ASSESSED])
        self.assertFalse(any(item.status is FindingStatus.FAIL for item in assessment.findings))

    def test_symlink_or_permission_denial_requires_review(self):
        assessment = assess_systemd_unit_metadata((
            UnitFileObservation("link.service", "/etc/systemd/system/link.service", 0, 0o777, False, True),
            UnitFileObservation("secret.service", "/etc/systemd/system/secret.service", None, None, None, False, "permission denied"),
        ))
        self.assertEqual(assessment.checks[0].status, FindingStatus.REVIEW)
        self.assertEqual(assessment.checks[1].status, FindingStatus.NOT_ASSESSED)
        self.assertFalse(any(item.status is FindingStatus.FAIL for item in assessment.findings))
