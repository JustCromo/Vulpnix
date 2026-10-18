import subprocess
import unittest

from vulpnix.areas.filesystem import FilesystemArea
from vulpnix.cli import report
from vulpnix.cli.legacy_bridge import area_result_to_scan_result
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaStatus, FindingStatus
from vulpnix.models import (
    CoverageStatus,
    FileMetadata,
    FileMetadataResult,
    FileMetadataStatus,
    FilesystemCoverage,
    SetIdFile,
)
from vulpnix.scan.privilege import PrivilegeContext

PRIVILEGED = PrivilegeContext(0, "PRIVILEGED")


def ctx(privilege=PRIVILEGED):
    return ExecutionContext(privilege, Environment.NATIVE)


def sensitive(path, mode=0o644, uid=0, gid=0, kind="regular file"):
    metadata = FileMetadata(path, uid, gid, mode, 1234, kind)
    status = FileMetadataStatus.COLLECTED if uid is not None and gid is not None else FileMetadataStatus.PARTIAL
    return FileMetadataResult(path, status, metadata)


def missing(path, reason="target is missing"):
    return FileMetadataResult(path, FileMetadataStatus.NOT_ASSESSED, None, reason)


def setid_file(path, mode=0o4755, uid=0, is_elf=True, options=("rw", "relatime")):
    return SetIdFile(FileMetadata(path, uid, 0, mode, 4096, "regular file"), is_elf, options)


def coverage(files=(), status=CoverageStatus.COLLECTED, review=()):
    return FilesystemCoverage(tuple(files), status, ("/usr", "/opt"), 100, 0.5, tuple(review))


GOOD = (
    sensitive("/etc/passwd"), sensitive("/etc/shadow", 0o600), sensitive("/etc/group"), sensitive("/etc/gshadow", 0o600),
)


def run(results=GOOD, cov=None, sensitive_error=None, setid_error=None, privilege=PRIVILEGED):
    def sensitive_collector():
        if sensitive_error is not None:
            raise sensitive_error
        return results

    def setid_collector():
        if setid_error is not None:
            raise setid_error
        return cov if cov is not None else coverage()

    return FilesystemArea(sensitive_collector, setid_collector).run(ctx(privilege))


def record(result, path):
    return next(r for r in result.records if r.key == path)


class FilesystemAreaTests(unittest.TestCase):
    def test_clean_system_is_complete_with_passing_records(self):
        result = run()
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual((result.findings, result.gaps), ((), ()))
        self.assertEqual([r.key for r in result.records], ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"])
        self.assertTrue(all(r.status is FindingStatus.PASS for r in result.records))
        self.assertEqual(record(result, "/etc/shadow").get("mode"), 0o600)

    def test_foreign_owner_and_world_writable_are_fail_findings_on_the_right_file(self):
        results = (sensitive("/etc/passwd", 0o666, uid=1000), *GOOD[1:])
        result = run(results)
        self.assertIs(record(result, "/etc/passwd").status, FindingStatus.FAIL)
        self.assertEqual({f.rule_id for f in result.findings}, {"FS-SENSITIVE-OWNER-001", "FS-SENSITIVE-WRITE-001"})
        self.assertTrue(all(f.status is FindingStatus.FAIL for f in result.findings))

    def test_world_readable_shadow_is_a_fail_finding(self):
        result = run((GOOD[0], sensitive("/etc/shadow", 0o644), *GOOD[2:]))
        self.assertEqual([f.rule_id for f in result.findings], ["FS-SECRET-WORLD-READ-001"])

    def test_group_readable_shadow_is_a_gap_and_a_review_record_not_a_finding(self):
        result = run((GOOD[0], sensitive("/etc/shadow", 0o640), *GOOD[2:]))
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertIs(record(result, "/etc/shadow").status, FindingStatus.REVIEW)
        self.assertEqual(result.findings, ())
        gap = result.gaps[0]
        self.assertEqual(gap.subject, "/etc/shadow")
        self.assertEqual(gap.message, "/etc/shadow: group-readable; group membership and policy were not assessed")

    def test_unavailable_file_is_a_not_assessed_record_and_a_gap(self):
        result = run((missing("/etc/gshadow", "permission denied reading metadata"), *GOOD[:3]))
        item = record(result, "/etc/gshadow")
        self.assertIs(item.status, FindingStatus.NOT_ASSESSED)
        self.assertIsNone(item.get("type"))
        self.assertEqual(item.get("collection_status"), "not_assessed")
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertEqual(result.findings, ())

    def test_unmapped_owner_is_a_gap_never_a_failure(self):
        result = run((sensitive("/etc/passwd", uid=None, gid=None), *GOOD[1:]))
        self.assertTrue(any("not mapped in the current user namespace" in g.message for g in result.gaps))
        self.assertEqual(result.findings, ())

    def test_world_writable_active_setid_elf_is_a_fail_finding(self):
        files = (setid_file("/usr/bin/su"), setid_file("/usr/bin/bad", mode=0o4777))
        result = run(cov=coverage(files))
        self.assertEqual([f.rule_id for f in result.findings], ["FS-SETID-WORLD-WRITE-001"])
        self.assertEqual([r.status for r in result.records if r.kind == "setid_file"], [None, FindingStatus.FAIL])
        self.assertEqual(next(f.raw for f in result.facts if f.key == "setid_active"), 2)

    def test_setid_mount_options_can_disable_the_bit(self):
        result = run(cov=coverage((setid_file("/opt/x", mode=0o4777, options=("nosuid",)),)))
        self.assertEqual(result.findings, ())
        self.assertEqual(next(f.raw for f in result.facts if f.key == "setid_disabled"), 1)

    def test_setid_review_statements_are_gaps_one_per_statement(self):
        cov = coverage((setid_file("/usr/bin/x", is_elf=None),), CoverageStatus.PARTIAL, ("/usr: directory could not be read: Permission denied",))
        result = run(cov=cov)
        keys = [g.key for g in result.gaps]
        self.assertIn("setid_review:0", keys)
        self.assertIn("setid_review:1", keys)
        self.assertIn("setid_coverage", keys)
        self.assertIs(result.status, AreaStatus.PARTIAL)

    def test_a_failing_collector_does_not_hide_the_other_one(self):
        for kwargs, expected_records in (
            ({"sensitive_error": OSError("boom")}, {"setid_file"}),
            ({"setid_error": subprocess.TimeoutExpired("x", 1)}, {"sensitive_file"}),
        ):
            with self.subTest(kwargs=list(kwargs)):
                result = run(cov=coverage((setid_file("/usr/bin/su"),)), **kwargs)
                self.assertIs(result.status, AreaStatus.PARTIAL)
                self.assertEqual({r.kind for r in result.records}, expected_records)
                self.assertTrue(any("could not be fully assessed" in g.message for g in result.gaps))

    def test_nothing_assessable_is_not_assessed_without_findings(self):
        result = run(sensitive_error=OSError("a"), setid_error=OSError("b"))
        self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
        self.assertEqual((result.findings, result.records), ((), ()))
        self.assertEqual(len(result.gaps), 2)


class FilesystemLegacyViewTests(unittest.TestCase):
    def section(self, result, details=False):
        legacy = area_result_to_scan_result(result, privilege=PRIVILEGED, scope=("filesystem metadata",), details=details)
        return legacy, legacy.sections[0]

    def lines(self, section, title):
        return next(block for block in section.blocks if block.title == title).lines

    def test_clean_view_matches_the_previous_wording(self):
        legacy, section = self.section(run())
        self.assertEqual(self.lines(section, "ASSESSMENT"), (
            "Permission checks completed for 4 regular file(s).",
            "Ownership verified for 4 file(s).",
            "No defined insecure condition detected among checks with reliable data.",
        ))
        self.assertEqual(self.lines(section, "REVIEW"), ("All defined filesystem checks completed without unresolved review items.",))
        self.assertEqual(self.lines(section, "DETAILS"), ("No files require additional detail.",))
        facts = self.lines(section, "FACTS")
        self.assertIn("Target files: 4", facts)
        self.assertIn("Metadata collected: 4/4", facts)
        self.assertIn("Ownership assessable: 4/4", facts)
        self.assertIs(legacy.coverage, AssessmentCoverage.COMPLETE)

    def test_review_lines_and_counts_for_group_readable_and_setid_gaps(self):
        results = (GOOD[0], sensitive("/etc/shadow", 0o640), *GOOD[2:])
        cov = coverage((setid_file("/usr/bin/x", is_elf=None),), CoverageStatus.PARTIAL, ("budget",))
        legacy, section = self.section(run(results, cov))
        review = self.lines(section, "REVIEW")
        self.assertIn("/etc/shadow: group-readable; group membership and policy were not assessed", review)
        self.assertIn("Set-ID: budget", review)
        self.assertIn("Set-ID: /usr/bin/x: ELF signature could not be verified", review)
        self.assertIn("Set-ID review items: 2", self.lines(section, "FACTS"))
        # old rule kept: one extra review item when set-ID coverage is not COLLECTED
        self.assertEqual(legacy.review_items, 1 + 2 + 1)
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)

    def test_details_list_every_file_with_setid_evidence_and_findings_block(self):
        cov = coverage((setid_file("/usr/bin/bad", mode=0o4777, options=("rw",)),))
        _, compact = self.section(run(cov=cov), details=False)
        _, detailed = self.section(run(cov=cov), details=True)
        self.assertEqual(len(self.lines(compact, "DETAILS")), 1)  # only the file with a finding
        lines = self.lines(detailed, "DETAILS")
        self.assertEqual(len(lines), 5)
        bad = next(line for line in lines if line.startswith("/usr/bin/bad"))
        self.assertIn("ELF: yes · mount options: rw", bad)
        self.assertIn("mode 4777", bad)
        self.assertEqual(self.lines(detailed, "FINDINGS")[1], "Rule: FS-SETID-WORLD-WRITE-001")
        self.assertFalse(any(block.title == "FINDINGS" for block in compact.blocks))

    def test_rootless_partial_result_still_asks_for_elevation(self):
        rootless = PrivilegeContext(1000, "ROOTLESS")
        result = run(cov=coverage((), CoverageStatus.PARTIAL, ("permission denied",)), privilege=rootless)
        legacy = area_result_to_scan_result(result, privilege=rootless, scope=("filesystem metadata",))
        self.assertEqual(legacy.privilege.mode, "ROOTLESS")
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)
        rendered = "\n".join(report.render_scan_report(
            report.ScanReport(host=None, sections=legacy.sections, findings=legacy.findings, scope=legacy.scope,
                              coverage=legacy.coverage, review_items=legacy.review_items, privilege=legacy.privilege), 80))
        self.assertIn("REVIEW REQUIRED", rendered)
        self.assertIn("current privileges", rendered)
        self.assertIn("sudo vulpnix", rendered)

    def test_when_both_collectors_fail_the_message_is_a_single_line(self):
        legacy, section = self.section(run(sensitive_error=OSError("a"), setid_error=OSError("b")))
        self.assertEqual(section.status, "NOT_ASSESSED")
        self.assertIn("could not be fully assessed", section.message)
        self.assertEqual(legacy.review_items, 2)


if __name__ == "__main__":
    unittest.main()
