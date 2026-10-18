import unittest

from vulpnix.areas.hardening import KernelHardeningArea
from vulpnix.cli.legacy_bridge import area_result_to_scan_result
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.collectors.hardening import HARDENING_KEYS
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaStatus, FindingStatus
from vulpnix.models import SysctlObservation
from vulpnix.rules.hardening import _RULES
from vulpnix.scan.privilege import PrivilegeContext

CTX = ExecutionContext(PrivilegeContext(0, "PRIVILEGED"), Environment.NATIVE)

SAFE = {
    "kernel.dmesg_restrict": "1",
    "kernel.kptr_restrict": "1",
    "kernel.yama.ptrace_scope": "1",
    "fs.protected_hardlinks": "1",
    "fs.protected_symlinks": "1",
    "fs.suid_dumpable": "0",
    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.default.accept_redirects": "0",
    "net.ipv4.conf.all.accept_source_route": "0",
    "net.ipv4.conf.default.accept_source_route": "0",
    "net.ipv4.conf.all.send_redirects": "0",
    "net.ipv4.conf.all.rp_filter": "1",
    "net.ipv6.conf.all.accept_redirects": "0",
    "net.ipv6.conf.default.accept_redirects": "0",
}


def observations(overrides=None, missing=None, errors=None):
    values = {**SAFE, **(overrides or {})}
    result = []
    for key in HARDENING_KEYS:
        if key in (missing or ()):
            result.append(SysctlObservation(key, None, "parameter is not present on this kernel"))
        elif key in (errors or {}):
            result.append(SysctlObservation(key, errors[key]))
        else:
            result.append(SysctlObservation(key, values[key]))
    return tuple(result)


def run(obs):
    return KernelHardeningArea(lambda: obs).run(CTX)


def fact(result, key):
    return next(item for item in result.facts if item.key == key)


class KernelHardeningAreaTests(unittest.TestCase):
    def test_safe_host_is_complete_with_a_passing_fact_per_parameter(self):
        result = run(observations())
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual((result.findings, result.gaps), ((), ()))
        self.assertEqual([f.key for f in result.facts], [rule.key for rule in _RULES])
        self.assertTrue(all(f.status is FindingStatus.PASS for f in result.facts))
        kptr = fact(result, "kernel.kptr_restrict")
        self.assertEqual((kptr.value, kptr.raw, kptr.detail), ("1", 1, "expected 1 or 2"))
        self.assertIn("Read-only", result.notes[0])

    def test_failing_value_is_a_failed_fact_and_a_fail_finding(self):
        result = run(observations({"kernel.kptr_restrict": "0"}))
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertIs(fact(result, "kernel.kptr_restrict").status, FindingStatus.FAIL)
        self.assertEqual([f.status for f in result.findings], [FindingStatus.FAIL])
        self.assertEqual(result.findings[0].title, "Restrict kernel pointer exposure")
        self.assertEqual(result.findings[0].severity, "MEDIUM")

    def test_context_sensitive_value_is_review_never_fail(self):
        result = run(observations({"fs.suid_dumpable": "2"}))
        item = fact(result, "fs.suid_dumpable")
        self.assertIs(item.status, FindingStatus.REVIEW)
        self.assertIn("appropriate for some host roles", item.detail)
        self.assertEqual([f.status for f in result.findings], [FindingStatus.REVIEW])

    def test_unreadable_required_parameter_is_a_gap_not_a_finding(self):
        result = run(observations(missing={"kernel.kptr_restrict"}))
        self.assertIs(result.status, AreaStatus.PARTIAL)
        item = fact(result, "kernel.kptr_restrict")
        self.assertEqual((item.value, item.raw, item.status), ("unavailable", None, FindingStatus.NOT_ASSESSED))
        self.assertEqual(result.findings, ())
        self.assertEqual(len(result.gaps), 1)
        self.assertIn("kernel.kptr_restrict", result.gaps[0].message)
        self.assertIn("not present on this kernel", result.gaps[0].message)

    def test_absent_optional_parameter_does_not_reduce_coverage(self):
        result = run(observations(missing={"kernel.yama.ptrace_scope", "net.ipv6.conf.all.accept_redirects"}))
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual(result.gaps, ())
        self.assertEqual(result.findings, ())
        self.assertIs(fact(result, "kernel.yama.ptrace_scope").status, FindingStatus.NOT_ASSESSED)

    def test_malformed_integer_is_a_gap_even_for_an_optional_parameter(self):
        result = run(observations(errors={"net.ipv6.conf.all.accept_redirects": "+-"}))
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertIs(fact(result, "net.ipv6.conf.all.accept_redirects").status, FindingStatus.ERROR)
        self.assertEqual(result.findings, ())
        self.assertIn("not an integer", result.gaps[0].message)

    def test_nothing_collected_is_not_assessed_without_findings(self):
        result = run(())
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertEqual(result.findings, ())
        required = sum(not rule.optional for rule in _RULES)
        self.assertEqual(len(result.gaps), required)
        self.assertEqual(len(result.facts), len(_RULES))

    def test_fact_statuses_always_match_the_rules_findings(self):
        result = run(observations({"kernel.dmesg_restrict": "0", "fs.suid_dumpable": "2"}))
        judged = {f.key: f.status for f in result.facts if f.status in (FindingStatus.FAIL, FindingStatus.REVIEW)}
        self.assertEqual(
            {f"KERNEL-HARDENING-{key.upper().replace('.', '-').replace('_', '-')}": status
             for key, status in judged.items()},
            {f.rule_id: f.status for f in result.findings},
        )


class HardeningLegacyViewTests(unittest.TestCase):
    def _legacy(self, result, details):
        legacy = area_result_to_scan_result(
            result, privilege=CTX.privilege, scope=("kernel hardening",), details=details
        )
        return legacy, legacy.sections[0]

    def test_counts_match_the_previous_view(self):
        values = {
            "kernel.kptr_restrict": "0",       # FAIL
            "fs.suid_dumpable": "2",           # REVIEW
            "net.ipv4.conf.default.accept_redirects": "1",  # REVIEW
        }
        legacy, section = self._legacy(run(observations(values)), details=False)
        facts = dict(section.facts)
        self.assertEqual(facts["Parameters checked"], "14")
        self.assertEqual(facts["Checks passing"], "11")
        self.assertEqual(facts["Verified concerns"], "1")
        self.assertEqual(facts["Context review"], "2")
        self.assertEqual(facts["Unavailable/error"], "0")
        self.assertEqual(section.items_label, "Items requiring attention:")
        self.assertEqual(len(section.items), 3)
        self.assertEqual(section.items[0], "[FAIL] Restrict kernel pointer exposure: 0")
        self.assertIs(legacy.coverage, AssessmentCoverage.COMPLETE)
        self.assertEqual(legacy.review_items, 0)
        self.assertEqual(section.blocks, ())

    def test_compact_attention_list_is_limited_and_details_list_every_check(self):
        values = {"net.ipv4.conf.all.accept_redirects": "1", "net.ipv4.conf.default.accept_redirects": "1",
                  "fs.suid_dumpable": "2", "net.ipv4.conf.all.send_redirects": "1",
                  "net.ipv4.conf.all.rp_filter": "0", "kernel.dmesg_restrict": "0",
                  "kernel.kptr_restrict": "0"}
        result = run(observations(values))
        _, compact = self._legacy(result, details=False)
        self.assertEqual(len(compact.items), 7)
        self.assertIn("1 additional check(s) omitted; use --details", compact.items[-1])
        _, detailed = self._legacy(result, details=True)
        self.assertIn("included in CHECK DETAILS", detailed.items[-1])
        block = detailed.blocks[0]
        self.assertEqual(block.title, "CHECK DETAILS")
        self.assertEqual(len(block.lines), 14)
        self.assertEqual(block.lines[0], "[FAIL] kernel.dmesg_restrict: observed=0; expected 1")

    def test_all_clear_view_says_so(self):
        _, section = self._legacy(run(observations()), details=False)
        self.assertEqual(section.items, ("All available hardening parameters matched the defined checks.",))
        self.assertEqual(section.items_label, "Assessment:")

    def test_partial_area_counts_unavailable_and_keeps_one_review_item_per_gap(self):
        legacy, section = self._legacy(run(observations(missing={"kernel.kptr_restrict"})), details=False)
        self.assertEqual(dict(section.facts)["Unavailable/error"], "1")
        self.assertEqual(section.items[0], "[NOT_ASSESSED] Restrict kernel pointer exposure: unavailable")
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)
        self.assertEqual(legacy.review_items, 1)
        self.assertEqual(legacy.findings, ())

    def test_when_nothing_is_assessable_the_view_still_shows_every_unavailable_check(self):
        legacy, section = self._legacy(run(()), details=False)
        facts = dict(section.facts)
        self.assertEqual((facts["Parameters checked"], facts["Checks passing"]), ("14", "0"))
        self.assertEqual(facts["Unavailable/error"], "14")
        self.assertEqual(len(section.items), 7)  # six attention items plus the omitted note
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)
        self.assertEqual(legacy.review_items, 11)


if __name__ == "__main__":
    unittest.main()
