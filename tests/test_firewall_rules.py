"""Tests for conservative firewall input-policy assessment."""

import unittest

from vulpnix.findings import FindingStatus
from vulpnix.models import (
    FirewallChain,
    FirewallObservation,
    FirewallRule,
    FirewallSnapshot,
)
from vulpnix.rules.firewall import assess_firewall_policy


def snapshot_for(*chains):
    observation = FirewallObservation(
        implementation="nftables",
        state="CONFIGURED",
        source="test fixture",
        summary="Test ruleset",
        chains=tuple(chains),
    )
    return FirewallSnapshot((observation,))


def input_chain(
    *,
    implementation="nftables",
    family="inet",
    table="filter",
    name="input",
    hook="input",
    policy="ACCEPT",
    rules=(),
    chain_type="filter",
):
    return FirewallChain(
        implementation=implementation,
        family=family,
        table=table,
        name=name,
        hook=hook,
        policy=policy,
        rules=tuple(rules),
        chain_type=chain_type,
    )


class FirewallPolicyAssessmentTests(unittest.TestCase):
    def test_accept_policy_without_fallback_deny_is_review(self):
        assessment = assess_firewall_policy(snapshot_for(input_chain()))
        self.assertEqual(len(assessment.findings), 1)
        finding = assessment.findings[0]
        self.assertEqual(finding.rule_id, "FIREWALL-INPUT-POLICY-001")
        self.assertIs(finding.status, FindingStatus.REVIEW)
        self.assertEqual(assessment.review_items, 1)
        self.assertIn("default policy ACCEPT", finding.evidence)

    def test_default_drop_policy_reports_chain_behavior(self):
        assessment = assess_firewall_policy(
            snapshot_for(input_chain(policy="DROP"))
        )
        self.assertEqual(assessment.findings, ())
        self.assertEqual(assessment.review_items, 0)
        self.assertIn("default policy DROP denies", assessment.checks[0])

    def test_unconditional_accept_is_review_even_with_drop_policy(self):
        chain = input_chain(
            policy="DROP",
            rules=(FirewallRule(1, "ACCEPT", True),),
        )
        assessment = assess_firewall_policy(snapshot_for(chain))
        self.assertEqual(
            assessment.findings[0].rule_id,
            "FIREWALL-INPUT-ACCEPT-001",
        )
        self.assertIs(assessment.findings[0].status, FindingStatus.REVIEW)

    def test_conditional_accept_before_unconditional_drop_remains_reviewed(self):
        chain = input_chain(
            policy="ACCEPT",
            rules=(
                FirewallRule(1, "ACCEPT", False),
                FirewallRule(2, "DROP", True),
            ),
        )
        assessment = assess_firewall_policy(snapshot_for(chain))
        finding_ids = {finding.rule_id for finding in assessment.findings}

        self.assertIn("FIREWALL-INPUT-ACCEPT-001", finding_ids)
        self.assertNotIn("FIREWALL-INPUT-POLICY-001", finding_ids)
        self.assertTrue(
            any("unconditional DROP" in check for check in assessment.checks)
        )

    def test_ignores_non_filter_and_non_input_chains(self):
        chains = (
            input_chain(name="prerouting", hook="prerouting"),
            input_chain(name="input_nat", chain_type="nat"),
        )
        assessment = assess_firewall_policy(snapshot_for(*chains))
        self.assertEqual(len(assessment.findings), 1)
        self.assertEqual(
            assessment.findings[0].rule_id,
            "FIREWALL-INPUT-UNASSESSED-001",
        )

    def test_missing_input_chain_reports_other_observed_hooks(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
        )
        assessment = assess_firewall_policy(snapshot_for(forward))

        self.assertEqual(len(assessment.findings), 2)
        by_id = {finding.rule_id: finding for finding in assessment.findings}

        self.assertIn("FIREWALL-INPUT-UNASSESSED-001", by_id)
        self.assertIn("FIREWALL-FORWARD-POLICY-001", by_id)

        finding = by_id["FIREWALL-INPUT-UNASSESSED-001"]
        self.assertIs(finding.status, FindingStatus.REVIEW)
        self.assertIn("hook=forward", finding.evidence)
        self.assertIn("policy=ACCEPT", finding.evidence)
        self.assertIn(
            "review support for the detected chain layout",
            finding.recommendation,
        )
        self.assertNotIn(
            "rerun the assessment with sufficient permissions",
            finding.recommendation,
        )

        forward_finding = by_id["FIREWALL-FORWARD-POLICY-001"]
        self.assertIs(forward_finding.status, FindingStatus.REVIEW)

    def test_empty_ruleset_is_not_treated_as_safe(self):
        observation = FirewallObservation(
            implementation="nftables",
            state="EMPTY",
            source="test fixture",
            summary="Empty ruleset",
        )
        assessment = assess_firewall_policy(FirewallSnapshot((observation,)))
        self.assertEqual(
            assessment.findings[0].rule_id,
            "FIREWALL-INPUT-UNASSESSED-001",
        )
        self.assertIs(assessment.findings[0].status, FindingStatus.REVIEW)

    def test_custom_chain_without_input_hook_is_not_analyzed_as_input(self):
        custom = input_chain(name="custom", hook=None, policy=None)
        observation = FirewallObservation(
            implementation="nftables",
            state="CONFIGURED",
            source="test fixture",
            summary="Custom chain only",
            chains=(custom,),
        )
        assessment = assess_firewall_policy(FirewallSnapshot((observation,)))
        self.assertEqual(
            assessment.findings[0].rule_id,
            "FIREWALL-INPUT-UNASSESSED-001",
        )


class FirewallForwardPolicyTests(unittest.TestCase):
    def test_forward_accept_policy_with_custom_chain_jump_is_review(self):
        chain = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(
                FirewallRule(1, "JUMP", True, "guest_cross"),
                FirewallRule(2, "JUMP", True, "guest_input"),
                FirewallRule(3, "JUMP", True, "guest_output"),
            ),
        )
        assessment = assess_firewall_policy(snapshot_for(chain))
        by_id = {finding.rule_id: finding for finding in assessment.findings}

        self.assertIn("FIREWALL-INPUT-UNASSESSED-001", by_id)
        self.assertIn("FIREWALL-FORWARD-POLICY-001", by_id)
        forward = by_id["FIREWALL-FORWARD-POLICY-001"]
        self.assertIs(forward.status, FindingStatus.REVIEW)
        self.assertIn("guest_cross", forward.evidence)
        self.assertIn("default policy ACCEPT", forward.evidence)

    def test_forward_reports_nested_accept_when_base_policy_is_unreachable(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(
                FirewallRule(1, "JUMP", True, "guest_input"),
                FirewallRule(2, "DROP", True),
            ),
        )
        guest_input = input_chain(
            name="guest_input",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "ACCEPT", True),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_input)
        )
        by_id = {finding.rule_id: finding for finding in assessment.findings}

        finding = by_id["FIREWALL-FORWARD-ACCEPT-001"]
        self.assertIs(finding.status, FindingStatus.REVIEW)
        self.assertIn("Bounded control-flow outcomes: ACCEPT", finding.evidence)
        self.assertNotIn("FIREWALL-FORWARD-POLICY-001", by_id)
        self.assertTrue(
            any(
                "default policy ACCEPT was not reachable" in check
                for check in assessment.checks
            )
        )

    def test_forward_does_not_misclassify_accept_after_jump(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="DROP",
            rules=(
                FirewallRule(1, "JUMP", True, "guest_input"),
                FirewallRule(2, "ACCEPT", True),
            ),
        )
        guest_input = input_chain(
            name="guest_input",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "DROP", True),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_input)
        )
        finding_ids = {item.rule_id for item in assessment.findings}

        self.assertNotIn("FIREWALL-FORWARD-ACCEPT-001", finding_ids)
        self.assertTrue(
            any("default policy DROP" in check for check in assessment.checks)
        )


    def test_forward_review_summarizes_custom_chain_actions(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(FirewallRule(1, "JUMP", True, "guest_input"),),
        )
        guest_input = input_chain(
            name="guest_input",
            hook=None,
            policy=None,
            rules=(
                FirewallRule(1, "ACCEPT", False),
                FirewallRule(2, "REJECT", False),
            ),
        )
        observation = FirewallObservation(
            implementation="nftables",
            state="CONFIGURED",
            source="test fixture",
            summary="Test ruleset",
            chains=(forward, guest_input),
        )
        assessment = assess_firewall_policy(FirewallSnapshot((observation,)))
        finding = next(
            item
            for item in assessment.findings
            if item.rule_id == "FIREWALL-FORWARD-POLICY-001"
        )

        self.assertIn("guest_input", finding.evidence)
        self.assertIn("rule 1=ACCEPT (conditional)", finding.evidence)
        self.assertIn("rule 2=REJECT (conditional)", finding.evidence)
        self.assertIn("does not prove that these conditions cover all traffic", finding.evidence)


    def test_forward_review_recursively_summarizes_nested_chain_actions(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(FirewallRule(1, "JUMP", True, "guest_input"),),
        )
        guest_input = input_chain(
            name="guest_input",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "JUMP", True, "guest_services"),),
        )
        guest_services = input_chain(
            name="guest_services",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "DROP", True),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_input, guest_services)
        )
        finding_ids = {item.rule_id for item in assessment.findings}

        self.assertNotIn("FIREWALL-FORWARD-POLICY-001", finding_ids)

        observation = next(
            check
            for check in assessment.checks
            if check.startswith("POLICY OBSERVED · ")
            and "default policy ACCEPT was not reachable" in check
        )

        self.assertIn("guest_services", observation)
        self.assertIn("rule 1=DROP (unconditional)", observation)
        self.assertIn("jump ->", observation)
        self.assertIn("Bounded control-flow outcomes: DROP", observation)

    def test_forward_review_reports_circular_chain_reference(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(FirewallRule(1, "JUMP", True, "guest_input"),),
        )
        guest_input = input_chain(
            name="guest_input",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "JUMP", True, "guest_services"),),
        )
        guest_services = input_chain(
            name="guest_services",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "GOTO", True, "guest_input"),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_input, guest_services)
        )
        finding = next(
            item for item in assessment.findings
            if item.rule_id == "FIREWALL-FORWARD-POLICY-001"
        )

        self.assertIn("circular chain reference detected", finding.evidence)

    def test_forward_review_reports_missing_nested_chain_metadata(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(FirewallRule(1, "JUMP", True, "guest_input"),),
        )
        guest_input = input_chain(
            name="guest_input",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "JUMP", True, "missing_nested_chain"),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_input)
        )
        finding = next(
            item for item in assessment.findings
            if item.rule_id == "FIREWALL-FORWARD-POLICY-001"
        )

        self.assertIn(
            "missing_nested_chain: chain metadata unavailable",
            finding.evidence,
        )

    def test_forward_review_preserves_empty_nested_chain_note(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(FirewallRule(1, "JUMP", True, "guest_input"),),
        )
        guest_input = input_chain(
            name="guest_input",
            hook=None,
            policy=None,
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_input)
        )
        finding = next(
            item for item in assessment.findings
            if item.rule_id == "FIREWALL-FORWARD-POLICY-001"
        )

        self.assertIn(
            "guest_input: no rule actions collected",
            finding.evidence,
        )

    def test_forward_return_prevents_later_drop_from_being_direct_verdict(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(
                FirewallRule(1, "RETURN", True),
                FirewallRule(2, "DROP", True),
            ),
        )

        assessment = assess_firewall_policy(snapshot_for(forward))
        finding = next(
            item for item in assessment.findings
            if item.rule_id == "FIREWALL-FORWARD-POLICY-001"
        )

        self.assertIn("default policy ACCEPT", finding.evidence)
        self.assertNotIn("unconditional DROP at rule 2", finding.evidence)

    def test_input_return_prevents_later_accept_from_being_direct_verdict(self):
        chain = input_chain(
            name="input",
            hook="input",
            policy="DROP",
            rules=(
                FirewallRule(1, "RETURN", True),
                FirewallRule(2, "ACCEPT", True),
            ),
        )

        assessment = assess_firewall_policy(snapshot_for(chain))
        finding_ids = {item.rule_id for item in assessment.findings}

        self.assertNotIn("FIREWALL-INPUT-ACCEPT-001", finding_ids)
        self.assertTrue(
            any(
                "default policy DROP denies" in check
                for check in assessment.checks
            )
        )


    def test_forward_unreachable_accept_policy_is_only_an_observation(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(FirewallRule(1, "JUMP", True, "guest_drop"),),
        )
        guest_drop = input_chain(
            name="guest_drop",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "DROP", True),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_drop)
        )
        finding_ids = {finding.rule_id for finding in assessment.findings}

        self.assertNotIn("FIREWALL-FORWARD-POLICY-001", finding_ids)
        self.assertTrue(
            any(
                "default policy ACCEPT was not reachable" in check
                for check in assessment.checks
            )
        )

    def test_nested_accept_is_reviewed_under_drop_policy(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="DROP",
            rules=(FirewallRule(1, "JUMP", True, "guest_accept"),),
        )
        guest_accept = input_chain(
            name="guest_accept",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "ACCEPT", True),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_accept)
        )
        by_id = {finding.rule_id: finding for finding in assessment.findings}

        self.assertIn("FIREWALL-FORWARD-ACCEPT-001", by_id)
        self.assertIs(
            by_id["FIREWALL-FORWARD-ACCEPT-001"].status,
            FindingStatus.REVIEW,
        )
        self.assertIn(
            "Bounded control-flow outcomes: ACCEPT",
            by_id["FIREWALL-FORWARD-ACCEPT-001"].evidence,
        )

    def test_goto_skips_calling_chain_rules_after_goto(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="DROP",
            rules=(FirewallRule(1, "JUMP", True, "outer"),),
        )
        outer = input_chain(
            name="outer",
            hook=None,
            policy=None,
            rules=(
                FirewallRule(1, "GOTO", True, "inner"),
                FirewallRule(2, "ACCEPT", True),
            ),
        )
        inner = input_chain(
            name="inner",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "RETURN", True),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, outer, inner)
        )
        finding_ids = {finding.rule_id for finding in assessment.findings}

        self.assertNotIn("FIREWALL-FORWARD-ACCEPT-001", finding_ids)
        self.assertTrue(
            any("default policy DROP denies" in check for check in assessment.checks)
        )

    def test_jump_return_resumes_callers_next_rule(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="DROP",
            rules=(
                FirewallRule(1, "JUMP", True, "guest_return"),
                FirewallRule(2, "ACCEPT", True),
            ),
        )
        guest_return = input_chain(
            name="guest_return",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "RETURN", True),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_return)
        )
        by_id = {finding.rule_id: finding for finding in assessment.findings}

        self.assertIn("FIREWALL-FORWARD-ACCEPT-001", by_id)
        self.assertIn(
            "Bounded control-flow outcomes: ACCEPT",
            by_id["FIREWALL-FORWARD-ACCEPT-001"].evidence,
        )

    def test_conditional_jump_keeps_match_and_nonmatch_paths(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(FirewallRule(1, "JUMP", False, "guest_drop"),),
        )
        guest_drop = input_chain(
            name="guest_drop",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "DROP", True),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, guest_drop)
        )
        finding = next(
            item
            for item in assessment.findings
            if item.rule_id == "FIREWALL-FORWARD-POLICY-001"
        )

        self.assertIn("DROP", finding.evidence)
        self.assertIn("POLICY_ACCEPT", finding.evidence)

    def test_cyclic_control_flow_remains_unresolved_and_reviewable(self):
        forward = input_chain(
            name="forward",
            hook="forward",
            policy="ACCEPT",
            rules=(FirewallRule(1, "JUMP", True, "chain_a"),),
        )
        chain_a = input_chain(
            name="chain_a",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "JUMP", True, "chain_b"),),
        )
        chain_b = input_chain(
            name="chain_b",
            hook=None,
            policy=None,
            rules=(FirewallRule(1, "GOTO", True, "chain_a"),),
        )

        assessment = assess_firewall_policy(
            snapshot_for(forward, chain_a, chain_b)
        )
        finding = next(
            item
            for item in assessment.findings
            if item.rule_id == "FIREWALL-FORWARD-POLICY-001"
        )

        self.assertIs(finding.status, FindingStatus.REVIEW)
        self.assertIn("UNRESOLVED", finding.evidence)

    def test_forward_drop_policy_is_observed_without_forward_finding(self):
        chain = input_chain(
            name="forward",
            hook="forward",
            policy="DROP",
        )
        assessment = assess_firewall_policy(snapshot_for(chain))
        ids = {finding.rule_id for finding in assessment.findings}

        self.assertIn("FIREWALL-INPUT-UNASSESSED-001", ids)
        self.assertNotIn("FIREWALL-FORWARD-POLICY-001", ids)
        self.assertTrue(
            any("default policy DROP" in check for check in assessment.checks)
        )



if __name__ == "__main__":
    unittest.main()
class FirewallFindingIdTests(unittest.TestCase):
    def test_ipv4_and_ipv6_findings_have_distinct_ids(self):
        from vulpnix.models.firewall import FirewallChain
        from vulpnix.rules.firewall import _family_rule_id

        common = {
            "implementation": "nftables",
            "table": "filter",
            "name": "forward",
            "hook": "forward",
            "policy": "ACCEPT",
        }
        ipv4 = FirewallChain(family="ip", **common)
        ipv6 = FirewallChain(family="ip6", **common)

        self.assertEqual(
            _family_rule_id("FIREWALL-FORWARD-POLICY-001", ipv4),
            "FIREWALL-FORWARD-POLICY-IPV4-001",
        )
        self.assertEqual(
            _family_rule_id("FIREWALL-FORWARD-POLICY-001", ipv6),
            "FIREWALL-FORWARD-POLICY-IPV6-001",
        )

    def test_inet_family_preserves_existing_id(self):
        from vulpnix.models.firewall import FirewallChain
        from vulpnix.rules.firewall import _family_rule_id

        chain = FirewallChain(
            implementation="nftables",
            family="inet",
            table="filter",
            name="forward",
            hook="forward",
            policy="ACCEPT",
        )

        self.assertEqual(
            _family_rule_id("FIREWALL-FORWARD-POLICY-001", chain),
            "FIREWALL-FORWARD-POLICY-001",
        )

