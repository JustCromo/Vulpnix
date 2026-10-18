import subprocess
import unittest

from vulpnix.areas.users import UsersArea, sudo_detail, users_error_message
from vulpnix.cli.legacy_bridge import area_result_to_scan_result
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core import AreaStatus, FindingStatus
from vulpnix.models import SudoGrant, SudoPrivilege, SudoPrivilegeStatus
from vulpnix.parsers.users import parse_local_users
from vulpnix.scan.privilege import PrivilegeContext

CTX = ExecutionContext(PrivilegeContext(0, "PRIVILEGED"), Environment.NATIVE)
R = SudoPrivilegeStatus
ALL = (SudoGrant(("ALL",), None, ("ALL",), ()),)

PASSWD = "\n".join((
    "root:x:0:0:Root:/root:/bin/sh",
    "service:x:0:10:Service:/nonexistent:/usr/sbin/nologin",
    "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
    "bob:x:1001:1001:Bob:/home/bob:",
))
GROUP = "\n".join(("root:x:0:", "users:x:1000:", "operators:x:2000:alice,bob", "service-group:x:10:service"))
SHADOW = "\n".join((
    "root:$6$h:1:0:99999:7::: ", "service:!:1:0:99999:7::: ",
    "alice:$6$h:1:0:99999:7::: ", "bob::1:0:99999:7::: ",
))
CLEAN = "root:x:0:0:Root:/root:/bin/sh\nalice:x:1000:1000:Alice:/home/alice:/bin/bash"
LOCKED = "\n".join(f"{name}:!:1:0:99999:7:::" for name in ("root", "service", "alice", "bob"))


def sudo(account, status, **kw):
    return SudoPrivilege(account, status, **kw)


def run(passwd=PASSWD, group=GROUP, shadow=SHADOW, sudo_results=(), sudo_error=None, users_error=None):
    def users():
        if users_error is not None:
            raise users_error
        return parse_local_users(passwd, group, shadow)

    def privileges(_users):
        if sudo_error is not None:
            raise sudo_error
        return sudo_results

    return UsersArea(users, privileges).run(CTX)


def fact(result, key):
    return next(item for item in result.facts if item.key == key)


def record(result, name):
    return next(item for item in result.records if item.key == name)


class UsersAreaTests(unittest.TestCase):
    def test_every_account_is_a_record_with_observed_fields(self):
        # bob has no primary-group entry, so give the fixture one: nothing is unknown.
        result = run(group=GROUP + "\nbob:x:1001:", shadow=LOCKED)
        self.assertIs(result.status, AreaStatus.COMPLETE)
        self.assertEqual([r.key for r in result.records], ["root", "service", "alice", "bob"])
        alice = record(result, "alice")
        self.assertEqual(alice.get("uid"), 1000)
        self.assertEqual(alice.get("groups"), ("users", "operators"))
        self.assertEqual(alice.get("shell"), "/bin/bash")
        self.assertIsNone(record(result, "bob").get("shell"))
        self.assertEqual(fact(result, "local_accounts").raw, 4)

    def test_only_root_with_uid_zero_passes(self):
        result = run(CLEAN, GROUP, None)
        uid0 = fact(result, "uid0_accounts")
        self.assertEqual((uid0.raw, uid0.status), (("root",), FindingStatus.PASS))

    def test_additional_uid_zero_is_a_review_observation_never_a_finding(self):
        result = run()
        uid0 = fact(result, "uid0_accounts")
        self.assertEqual(uid0.raw, ("root", "service"))
        self.assertIs(uid0.status, FindingStatus.REVIEW)
        self.assertEqual(result.findings, ())
        self.assertFalse(any(g.key.startswith("uid0") for g in result.gaps))

    def test_privileged_state_is_verified_or_unknown_never_assumed(self):
        results = (
            sudo("alice", R.PRIVILEGES_FOUND, grants=ALL),
            sudo("bob", R.NO_PRIVILEGES),
        )
        result = run(passwd=PASSWD + "\ncarol:x:1002:1002::/home/carol:/bin/sh", sudo_results=results)
        states = {r.key: r.get("privileged") for r in result.records}
        self.assertEqual(states, {"root": True, "service": True, "alice": True, "bob": False, "carol": None})
        self.assertEqual(fact(result, "privileged_accounts").raw, ("root", "service", "alice"))
        self.assertEqual(fact(result, "sudo_accounts").raw, ("alice",))
        self.assertEqual(fact(result, "sudo_no_privileges").raw, ("bob",))

    def test_account_with_a_normal_password_is_currently_reported_as_state_unavailable(self):
        # Characterization of existing behavior, kept on purpose: the parser only
        # sets an account state for locked or empty-password accounts, so an
        # account with an ordinary password hash has state None and is counted
        # as "could not be evaluated". Update this test if that rule changes.
        result = run(CLEAN, GROUP, "root:$6$h:1:0:::::\nalice:$6$h:1:0:::::")
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertEqual({g.subject for g in result.gaps}, {"root", "alice"})
        self.assertTrue(all(g.cause == "account state unavailable" for g in result.gaps))

    def test_missing_account_state_or_groups_is_one_gap_per_account(self):
        result = run(group=None, shadow=None)
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertEqual(len(result.gaps), 4)
        gap = next(g for g in result.gaps if g.subject == "alice")
        self.assertEqual(gap.key, "account_incomplete:alice")
        self.assertEqual(gap.cause, "account state and group membership unavailable")
        self.assertEqual(result.findings, ())

    def test_unevaluated_sudo_results_become_gaps_grouped_by_cause(self):
        results = (
            sudo("alice", R.NOT_ASSESSED, reason="permission denied while inspecting another account"),
            sudo("bob", R.NOT_ASSESSED, reason="permission denied while inspecting another account"),
            sudo("root", R.NOT_ASSESSED, reason="something unexpected"),
            sudo("service", R.UNAVAILABLE, reason="sudo is not installed or not available in standard executable paths"),
        )
        result = run(CLEAN, GROUP, "root:!:1:0:::::\nalice:!:1:0:::::", sudo_results=results)
        gaps = {g.key: g for g in result.gaps}
        self.assertEqual(gaps["sudo_not_assessed:alice"].cause, "permission denied while inspecting another account")
        self.assertEqual(gaps["sudo_not_assessed:alice"].cause, gaps["sudo_not_assessed:bob"].cause)
        self.assertEqual(gaps["sudo_not_assessed:root"].cause, "sudo privilege state could not be established")
        self.assertEqual(gaps["sudo_unavailable:service"].subject, "service")
        self.assertIs(result.status, AreaStatus.PARTIAL)

    def test_unreadable_account_database_is_not_assessed_with_a_clear_reason(self):
        cases = {
            FileNotFoundError("x"): "could not be found",
            PermissionError("x"): "could not be read",
            UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad"): "unreadable text",
            ValueError("line 3: bad entry"): "malformed: line 3: bad entry",
            OSError("boom"): "Local account data is unavailable.",
        }
        for error, expected in cases.items():
            with self.subTest(error=type(error).__name__):
                result = run(users_error=error)
                self.assertIs(result.status, AreaStatus.NOT_ASSESSED)
                self.assertEqual((result.findings, result.records), ((), ()))
                self.assertIn(expected, result.gaps[0].message)
                self.assertEqual(result.gaps[0].key, "local-accounts-unavailable")

    def test_error_message_checks_unicode_before_value_error(self):
        self.assertIn("unreadable text", users_error_message(UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")))

    def test_sudo_collection_failure_keeps_accounts_and_says_privileges_are_unknown(self):
        result = run(sudo_error=subprocess.TimeoutExpired("sudo", 5))
        self.assertIs(result.status, AreaStatus.PARTIAL)
        self.assertEqual(len(result.records), 4)
        self.assertEqual(result.gaps[0].key, "sudo-collection-failed")
        self.assertEqual(fact(result, "sudo_accounts").raw, ())
        self.assertIsNone(record(result, "alice").get("privileged"))
        self.assertEqual(record(result, "alice").get("sudo"), "sudo: NOT_ASSESSED")

    def test_sudo_detail_reports_grants_or_the_reason(self):
        grant = SudoGrant(("root",), ("wheel",), ("/usr/bin/id",), ("NOPASSWD",), "/etc/sudoers:3")
        self.assertEqual(
            sudo_detail(sudo("a", R.PRIVILEGES_FOUND, grants=(grant,), host="h1")),
            "sudo: host=h1 runas=root:wheel commands=/usr/bin/id options=NOPASSWD source=/etc/sudoers:3",
        )
        self.assertEqual(sudo_detail(sudo("a", R.NO_PRIVILEGES, reason="none")), "sudo: no_privileges (none)")
        self.assertEqual(sudo_detail(None), "sudo: NOT_ASSESSED")


class UsersLegacyViewTests(unittest.TestCase):
    def _section(self, result, details=False):
        legacy = area_result_to_scan_result(result, privilege=None, scope=("users",), details=details)
        return legacy, legacy.sections[0]

    def _lines(self, section, title):
        return next(block for block in section.blocks if block.title == title).lines

    def test_compact_view_has_assessment_review_and_details_blocks(self):
        results = (sudo("alice", R.PRIVILEGES_FOUND, grants=ALL),)
        legacy, section = self._section(run(CLEAN, GROUP, "root:!:1:0:::::\nalice:!:1:0:::::", sudo_results=results))
        self.assertEqual(
            self._lines(section, "ASSESSMENT"),
            ("✓ Only one UID 0 account detected: root",
             "✓ Privileged access verified for 2 accounts",
             "✓ Sudo access verified for 1 account"),
        )
        self.assertEqual(self._lines(section, "REVIEW"), ("No unresolved account information",))
        self.assertEqual(
            next(b for b in section.blocks if b.title == "DETAILS").lists,
            (("UID 0", ("root",)), ("Privileged", ("root", "alice")), ("Sudo access", ("alice",))),
        )
        self.assertEqual(dict(section.facts), {"Local accounts": "2", "UID 0 accounts": "1", "Privileged accounts": "2"})
        self.assertIs(legacy.coverage, AssessmentCoverage.COMPLETE)

    def test_additional_uid_zero_is_listed_for_review_without_findings(self):
        legacy, section = self._section(run())
        self.assertIn("Additional UID 0 accounts detected: service", self._lines(section, "ASSESSMENT"))
        self.assertIn(
            "Review authorization for additional UID 0 accounts: service", self._lines(section, "REVIEW")
        )
        self.assertEqual(legacy.findings, ())

    def test_review_lines_count_accounts_and_group_sudo_reasons(self):
        results = (
            sudo("alice", R.NOT_ASSESSED, reason="permission denied while inspecting another account"),
            sudo("bob", R.NOT_ASSESSED, reason="permission denied while inspecting another account"),
        )
        legacy, section = self._section(run(group=None, sudo_results=results))
        review = self._lines(section, "REVIEW")
        self.assertIn("2 accounts: permission denied while inspecting another account", review)
        self.assertIn("Group membership unavailable for 4 accounts", review)
        self.assertEqual(legacy.review_items, 4 + 2)
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)

    def test_details_list_the_full_account_inventory(self):
        results = (sudo("alice", R.PRIVILEGES_FOUND, grants=ALL), sudo("bob", R.NO_PRIVILEGES))
        _, section = self._section(run(shadow=None, sudo_results=results), details=True)
        inventory = self._lines(section, "ACCOUNT INVENTORY")
        self.assertEqual(len(inventory), 4)
        self.assertIn(
            "alice · UID 1000 · GID 1000 · groups: users, operators · shell: /bin/bash · "
            "privileged: yes · account state: NOT_ASSESSED · sudo: runas=ALL commands=ALL",
            inventory,
        )
        self.assertIn(
            "bob · UID 1001 · GID 1001 · groups: Unavailable · shell: Unavailable · "
            "privileged: no · account state: NOT_ASSESSED · sudo: no_privileges",
            inventory,
        )

    def test_not_assessed_area_has_a_single_clear_message(self):
        legacy, section = self._section(run(users_error=FileNotFoundError("x")))
        self.assertEqual(section.status, "NOT_ASSESSED")
        self.assertEqual(section.message, "The local passwd database could not be found.")
        self.assertIs(legacy.coverage, AssessmentCoverage.PARTIAL)
        self.assertEqual(legacy.review_items, 1)

    def test_sudo_collection_failure_is_listed_as_a_review_line(self):
        _, section = self._section(run(sudo_error=OSError("sudo exploded")))
        self.assertTrue(any("sudo privileges could not be collected" in line for line in self._lines(section, "REVIEW")))


if __name__ == "__main__":
    unittest.main()
