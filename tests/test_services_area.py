import subprocess
import unittest
from unittest.mock import Mock

from vulpnix.areas.services import ServicesArea, UnitFilesArea, observe_services, services_error_message
from vulpnix.cli.legacy_bridge import area_result_to_scan_result
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaStatus, FindingStatus
from vulpnix.engine import run_area
from vulpnix.models import Service, UnitFileObservation
from vulpnix.scan.privilege import PrivilegeContext


def make_ctx():
    return ExecutionContext(PrivilegeContext(0, "PRIVILEGED"), Environment.NATIVE)


def svc(name, state="active", enabled=True, unit_file_state="enabled"):
    return Service(name, state, enabled, None, "systemd", unit_file_state)


P = "/etc/systemd/system/"


def obs(unit, path, uid=0, mode=0o644, regular=True, link=False, error=None):
    return UnitFileObservation(unit, path, uid, mode, regular, link, error)


class ServicesAreaTests(unittest.TestCase):
    def run_services(self, services=None, error=None, ctx=None):
        def collector():
            if error is not None:
                raise error
            return services
        return ServicesArea(collector).run(ctx or make_ctx())

    def test_every_service_is_a_record_with_observed_fields(self):
        result = self.run_services((svc("a.service"), svc("b.service", "inactive", False, "disabled")))
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual([r.key for r in result.records], ["a.service", "b.service"])
        self.assertEqual(result.records[1].get("state"), "inactive")
        self.assertIs(result.records[1].get("enabled"), False)
        self.assertEqual(result.facts[0].raw, 2)
        self.assertEqual((result.findings, result.gaps), ((), ()))

    def test_known_non_boolean_unit_states_are_not_unknown(self):
        services = (
            svc("static.service", "inactive", None, "static"),
            svc("generated.service", "active", None, "generated"),
            svc("unknown.service", "active", None, "unknown"),
        )
        result = self.run_services(services)
        self.assertEqual([g.subject for g in result.gaps], ["unknown.service"])
        self.assertEqual(result.gaps[0].cause, "startup enablement unknown")
        self.assertIs(result.status, AreaStatus.PARTIAL)
        legacy = area_result_to_scan_result(result, privilege=None, scope=("services",))
        self.assertEqual(dict(legacy.sections[0].facts)["Startup enabled"], "0 yes · 0 no · 2 non-boolean · 1 unknown")
        self.assertEqual(legacy.review_items, 1)

    def test_unknown_state_and_enablement_are_named_together(self):
        result = self.run_services((svc("x.service", "unknown", None, None),))
        self.assertEqual(result.gaps[0].cause, "state and startup enablement unknown")

    def test_a_failing_systemd_is_not_assessed_with_a_reason(self):
        cases = {
            FileNotFoundError("x"): "systemctl is not installed.",
            subprocess.TimeoutExpired("systemctl", 10): "systemctl did not respond in time.",
            subprocess.CalledProcessError(1, "systemctl"): "systemd could not be queried; access may be restricted.",
            ValueError("bad"): "systemd returned unreadable service data.",
            OSError("boom"): "systemd service data is unavailable.",
        }
        for error, expected in cases.items():
            with self.subTest(error=type(error).__name__):
                result = self.run_services(error=error)
                self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
                self.assertEqual((result.records, result.findings), ((), ()))
                self.assertEqual(result.gaps[0].message, expected)
                self.assertEqual(result.gaps[0].message, services_error_message(error))

    def test_legacy_view_lists_active_startup_enabled_services_with_a_limit(self):
        many = tuple(svc(f"s{i:02d}.service") for i in range(70))
        result = self.run_services(many)
        compact = area_result_to_scan_result(result, privilege=None, scope=(), details=False).sections[0]
        self.assertEqual(len(compact.items), 9)
        self.assertIn("62 additional service(s) omitted; use --details", compact.items[-1])
        detailed = area_result_to_scan_result(result, privilege=None, scope=(), details=True).sections[0]
        self.assertEqual(len(detailed.items), 61)
        self.assertIn("10 additional service(s) omitted", detailed.items[-1])
        self.assertEqual(compact.items_label, "Active now and enabled to start at boot:")

    def test_legacy_view_when_nothing_is_active_and_enabled(self):
        section = area_result_to_scan_result(self.run_services((svc("a.service", "inactive", False, "disabled"),)),
                                             privilege=None, scope=()).sections[0]
        self.assertEqual(section.items, ("No active, startup-enabled services found.",))
        self.assertIsNone(section.items_label)


class UnitFilesAreaTests(unittest.TestCase):
    def run_units(self, observations=(), notes=(), services=(svc("a.service"),), services_error=None, collector_error=None, ctx=None):
        def services_collector():
            if services_error is not None:
                raise services_error
            return services

        def collector(_services):
            if collector_error is not None:
                raise collector_error
            return observations, notes

        return UnitFilesArea(collector, services_collector).run(ctx or make_ctx())

    def test_safe_files_are_complete_with_passing_records(self):
        result = self.run_units((obs("a.service", P + "a.service"),))
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual((result.findings, result.gaps), ((), ()))
        self.assertIs(result.records[0].status, FindingStatus.PASS)
        self.assertEqual(result.records[0].get("unit"), "a.service")
        self.assertIn("File contents are not read", result.notes[0])

    def test_writable_or_foreign_owned_file_is_failed_with_a_fail_finding(self):
        result = self.run_units((obs("a.service", P + "a.service", uid=1000, mode=0o666),))
        self.assertEqual([r.status for r in result.records], [FindingStatus.FAIL])
        self.assertEqual([f.status for f in result.findings], [FindingStatus.FAIL])
        self.assertEqual(result.findings[0].severity, "HIGH")
        self.assertIn("owner UID 1000 is not root", result.records[0].get("evidence"))

    def test_symlink_is_review_and_never_a_failure(self):
        result = self.run_units((obs("a.service", P + "a.service", mode=0o777, regular=False, link=True),))
        self.assertEqual([f.status for f in result.findings], [FindingStatus.REVIEW])

    def test_uninspectable_file_is_a_record_and_a_gap_but_never_a_finding(self):
        result = self.run_units((obs("a.service", P + "a.service"), obs("b.service", P + "b.service", None, None, None, False, "permission denied")))
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertIs(result.records[1].status, FindingStatus.NOT_ASSESSED)
        self.assertEqual(result.findings, ())
        gap = result.gaps[0]
        self.assertEqual((gap.subject, gap.cause), ("b.service", "permission denied"))
        self.assertIn("permission denied", gap.message)

    def test_collector_notes_become_gaps_and_make_the_area_partial(self):
        result = self.run_units((obs("a.service", P + "a.service"),), notes=("unit budget reached", "template skipped"))
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertEqual([g.message for g in result.gaps], ["unit budget reached", "template skipped"])

    def test_nothing_inspected_is_not_assessed(self):
        result = self.run_units((), notes=("No service units were available for unit-file metadata assessment",))
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertEqual(result.findings, ())

    def test_an_area_that_examined_nothing_never_reports_complete(self):
        result = self.run_units((), notes=())
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertEqual(result.gaps[0].key, "nothing-inspected")

    def test_missing_services_make_the_area_not_assessed_with_the_same_reason(self):
        for error in (FileNotFoundError("x"), subprocess.TimeoutExpired("systemctl", 10)):
            with self.subTest(error=type(error).__name__):
                result = self.run_units(services_error=error)
                self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
                self.assertEqual(result.gaps[0].message, f"Unit-file metadata is unavailable: {services_error_message(error)}")
                self.assertEqual(result.records, ())

    def test_a_failing_unit_file_collector_is_not_assessed(self):
        result = self.run_units(collector_error=subprocess.CalledProcessError(1, "systemctl"))
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertIn("systemd could not be queried", result.gaps[0].message)

    def test_unit_file_view_counts_and_shows_all_coverage_notes_with_details(self):
        link = obs("demo.service", "/usr/lib/systemd/system/demo.service", mode=0o777, regular=False, link=True)
        notes = tuple(f"coverage issue {i}" for i in range(1, 6))
        result = self.run_units((link,), notes=notes)
        detailed = area_result_to_scan_result(result, privilege=None, scope=(), details=True).sections[0]
        self.assertEqual(dict(detailed.facts)["Review"], "6")
        self.assertEqual([i for i in detailed.items if i.startswith("REVIEW: ")], [f"REVIEW: {n}" for n in notes])
        compact = area_result_to_scan_result(result, privilege=None, scope=(), details=False).sections[0]
        self.assertIn("2 additional coverage review item(s) omitted", compact.items[-1])

    def test_unit_file_view_limits_the_attention_list(self):
        many = tuple(obs(f"u{i}.service", f"{P}u{i}.service", uid=1000) for i in range(12))
        legacy = area_result_to_scan_result(self.run_units(many), privilege=None, scope=(), details=False)
        items = legacy.sections[0].items
        self.assertEqual(len(items), 9)
        self.assertIn("4 additional item(s) omitted", items[-1])
        self.assertIs(legacy.coverage, AssessmentCoverage.COMPLETE)
        self.assertEqual(len(legacy.findings), 12)


class SharedObservationTests(unittest.TestCase):
    def test_services_and_unit_files_read_systemd_once_per_context(self):
        collector = Mock(return_value=(svc("a.service"),))
        ctx = make_ctx()
        services = ServicesArea(collector).run(ctx)
        units = UnitFilesArea(lambda s: ((), ()), collector).run(ctx)
        self.assertEqual(collector.call_count, 1)
        self.assertIs(services.status, AreaStatus.COMPLETE)
        self.assertIs(units.status, AreaStatus.NOT_ASSESSED)  # nothing to inspect, but no second read

    def test_a_failed_observation_fails_both_areas_for_the_same_reason(self):
        collector = Mock(side_effect=subprocess.TimeoutExpired("systemctl", 10))
        ctx = make_ctx()
        services = ServicesArea(collector).run(ctx)
        units = UnitFilesArea(lambda s: ((), ()), collector).run(ctx)
        self.assertEqual(collector.call_count, 1)
        self.assertIn("did not respond in time", services.gaps[0].message)
        self.assertIn("did not respond in time", units.gaps[0].message)

    def test_the_observation_records_where_and_when_the_services_came_from(self):
        ctx = make_ctx()
        observe_services(ctx, lambda: (svc("a.service"),))
        item = ctx.observations.peek("systemd.services")
        self.assertIn("systemctl", item.source)
        self.assertEqual(len(item.value), 1)

    def test_run_area_keeps_isolation_for_unexpected_collector_errors(self):
        area = ServicesArea(Mock(side_effect=KeyError("bug")))
        with self.assertRaises(KeyError):
            run_area(area, make_ctx())


if __name__ == "__main__":
    unittest.main()
