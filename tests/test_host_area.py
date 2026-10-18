import io
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

from vulpnix.areas.host import HostArea
from vulpnix.areas.host import area as host_area
from vulpnix.cli import app
from vulpnix.areas.services import area as services_area
from vulpnix.cli.legacy_bridge import area_result_to_scan_result
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaStatus
from vulpnix.models import SystemInfo
from vulpnix.scan.orchestrator import ScanOrchestrator
from vulpnix.scan.privilege import PrivilegeContext

INFO = SystemInfo(
    hostname="archlinux",
    distribution="Arch Linux",
    distribution_version="2026.10",
    kernel_release="7.2.8-arch1-2",
    architecture="x86_64",
    uptime_seconds=90061.5,
)


def ctx(environment=Environment.NATIVE):
    return ExecutionContext(PrivilegeContext(1000, "ROOTLESS"), environment)


def run(info=INFO, error=None, environment=Environment.NATIVE):
    def collector():
        if error is not None:
            raise error
        return info
    return HostArea(collector).run(ctx(environment))


class HostAreaTests(unittest.TestCase):
    def test_reports_identity_facts_with_typed_raw_values(self):
        result = run()
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual((result.findings, result.gaps), ((), ()))
        facts = {fact.key: fact for fact in result.facts}
        self.assertEqual(facts["hostname"].value, "archlinux")
        self.assertEqual(facts["kernel_release"].label, "Kernel")
        self.assertEqual(facts["uptime"].value, "1d 1h 1m")
        self.assertEqual(facts["uptime"].raw, 90061.5)
        self.assertTrue(all(fact.status is None for fact in result.facts))

    def test_missing_values_read_unavailable_with_no_raw_value(self):
        result = run(SystemInfo(hostname="h"))
        facts = {fact.key: fact for fact in result.facts}
        self.assertEqual(facts["distribution"].value, "Unavailable")
        self.assertIsNone(facts["distribution"].raw)
        self.assertEqual(facts["uptime"].value, "Unavailable")
        self.assertIs(result.status, AreaStatus.COMPLETE)

    def test_host_values_are_made_printable_and_bounded(self):
        result = run(SystemInfo(hostname="evil\x1b[2Jhost" + "x" * 100))
        hostname = result.facts[0]
        self.assertNotIn("\x1b", hostname.value)
        self.assertLessEqual(len(hostname.value), 80)
        self.assertTrue(hostname.value.endswith("…"))
        self.assertIn("\x1b", hostname.raw)  # the observed value is kept as observed

    def test_unreadable_host_facts_are_not_assessed_with_a_reason(self):
        result = run(error=OSError("host facts unavailable"))
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertEqual(result.facts, ())
        self.assertEqual(result.gaps[0].key, "host-facts-unavailable")
        self.assertIn("could not be collected reliably", result.gaps[0].message)
        self.assertIn("host facts unavailable", result.gaps[0].message)

    def test_non_linux_is_reported_as_unsupported_not_as_a_crash(self):
        result = run(error=NotImplementedError("Linux only"))
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertEqual(result.gaps[0].key, "unsupported-platform")
        self.assertIn("Linux only", result.gaps[0].message)

    def test_environment_is_a_fact_and_wsl_or_container_adds_a_scope_note(self):
        native = run()
        self.assertEqual(
            next(f for f in native.facts if f.key == "environment").value, "Native Linux"
        )
        self.assertEqual(native.notes, ())

        wsl = run(environment=Environment.WSL)
        env = next(f for f in wsl.facts if f.key == "environment")
        self.assertEqual((env.value, env.raw), ("WSL", "WSL"))
        self.assertIn("not assessed", wsl.notes[0])

        container = run(environment=Environment.CONTAINER)
        self.assertIn("container host", container.notes[0])
        self.assertEqual(run(environment=Environment.UNKNOWN).notes, ())


class HostLegacyBridgeTests(unittest.TestCase):
    def test_legacy_section_keeps_the_five_identity_rows(self):
        legacy = area_result_to_scan_result(run(), privilege=None, scope=("system facts",))
        section = legacy.sections[0]
        self.assertEqual(section.title, "SYSTEM")
        self.assertEqual(
            section.facts,
            (
                ("Hostname", "archlinux"),
                ("Distribution", "Arch Linux (2026.10)"),
                ("Kernel", "7.2.8-arch1-2"),
                ("Architecture", "x86_64"),
                ("Uptime", "1d 1h 1m"),
            ),
        )
        self.assertIs(legacy.coverage, AssessmentCoverage.COMPLETE)
        self.assertEqual(legacy.review_items, 0)

    def test_legacy_distribution_omits_version_when_unknown(self):
        legacy = area_result_to_scan_result(
            run(SystemInfo(distribution="Example Linux")), privilege=None, scope=()
        )
        self.assertEqual(dict(legacy.sections[0].facts)["Distribution"], "Example Linux")

    def test_typed_host_identity_is_rebuilt_for_the_renderers(self):
        legacy = area_result_to_scan_result(run(), privilege=None, scope=())
        self.assertEqual(legacy.host, INFO)

    def test_unavailable_host_has_no_identity_and_is_partial(self):
        legacy = area_result_to_scan_result(run(error=OSError("x")), privilege=None, scope=())
        self.assertIsNone(legacy.host)
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)
        self.assertEqual(legacy.review_items, 1)
        self.assertEqual(legacy.sections[0].status, "NOT_ASSESSED")


class HostCliTests(unittest.TestCase):
    def test_unsupported_platform_stops_the_full_scan_with_one_clear_section(self):
        output = io.StringIO()
        with (
            patch.object(host_area, "collect_system_info", side_effect=NotImplementedError("Linux only")),
            patch.object(services_area, "collect_services") as services,
            redirect_stdout(output),
        ):
            app._dispatch_command("scan")
        rendered = output.getvalue()
        self.assertIn("supported on Linux only", rendered)
        self.assertIn("NOT_ASSESSED", rendered)
        self.assertIn("FINAL RESULT", rendered)
        services.assert_not_called()

    def test_scan_host_failure_stops_with_the_reason_and_reports_failure(self):
        output = io.StringIO()
        with (
            patch.object(host_area, "collect_system_info", side_effect=OSError("boom")),
            redirect_stdout(output),
        ):
            shown = app._show_host_assessment("HOST DETAILS")
        self.assertFalse(shown)
        self.assertIn("HOST DETAILS", output.getvalue())
        self.assertIn("boom", output.getvalue())


class SinglePrivilegeSourceTests(unittest.TestCase):
    def test_orchestrator_and_areas_share_one_privilege_source(self):
        rootless = PrivilegeContext(1000, "ROOTLESS")
        with patch("vulpnix.context.execution.current_privilege_context", return_value=rootless):
            self.assertEqual(ScanOrchestrator()._privilege, rootless)


if __name__ == "__main__":
    unittest.main()
