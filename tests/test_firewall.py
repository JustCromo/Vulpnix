"""Tests for normalized read-only firewall observations."""

import json
import subprocess
import unittest
from unittest.mock import patch

from vulpnix.collectors import firewall


class NftablesParserTests(unittest.TestCase):
    def test_counts_ipv4_and_ipv6_tables_chains_and_rules(self):
        payload = {
            "nftables": [
                {"metainfo": {"version": "1.0"}},
                {"table": {"family": "ip", "name": "filter"}},
                {
                    "chain": {
                        "family": "ip",
                        "table": "filter",
                        "name": "input",
                        "hook": "input",
                        "policy": "drop",
                    }
                },
                {
                    "rule": {
                        "family": "ip",
                        "table": "filter",
                        "chain": "input",
                        "expr": [],
                    }
                },
                {"table": {"family": "ip6", "name": "filter6"}},
                {
                    "chain": {
                        "family": "ip6",
                        "table": "filter6",
                        "name": "input",
                        "hook": "input",
                        "policy": "drop",
                    }
                },
                {
                    "rule": {
                        "family": "ip6",
                        "table": "filter6",
                        "chain": "input",
                        "expr": [],
                    }
                },
            ]
        }

        observation = firewall._parse_nft_json(json.dumps(payload))

        self.assertEqual(observation.implementation, "nftables")
        self.assertEqual(observation.state, "CONFIGURED")
        self.assertIn("tables=2", observation.details)
        self.assertIn("chains=2", observation.details)
        self.assertIn("rules=2", observation.details)
        self.assertIn("families=ip,ip6", observation.details)

    def test_empty_nft_ruleset_is_not_a_security_verdict(self):
        observation = firewall._parse_nft_json('{"nftables": []}')

        self.assertEqual(observation.state, "EMPTY")
        self.assertIn("rules=0", observation.details)
        self.assertIn("not a security verdict", observation.summary.lower())


class IptablesSaveParserTests(unittest.TestCase):
    def test_normalizes_ipv4_and_ipv6_rules_and_default_policies(self):
        ipv4 = """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
"""
        ipv6 = """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p ipv6-icmp -j ACCEPT
COMMIT
"""

        v4 = firewall._parse_iptables_save(
            ipv4, implementation="iptables"
        )
        v6 = firewall._parse_iptables_save(
            ipv6, implementation="ip6tables"
        )

        self.assertEqual(v4.state, "CONFIGURED")
        self.assertIn("families=ipv4", v4.details)
        self.assertIn("rules=1", v4.details)
        self.assertIn("INPUT=DROP", v4.details)

        self.assertEqual(v6.state, "CONFIGURED")
        self.assertIn("families=ipv6", v6.details)
        self.assertIn("rules=1", v6.details)


if __name__ == "__main__":
    unittest.main()


class FirewallMalformedOutputTests(unittest.TestCase):
    def test_invalid_nft_json_is_an_error_not_an_empty_ruleset(self):
        observation = firewall._parse_nft_json("not valid json")

        self.assertEqual(observation.state, "ERROR")
        self.assertTrue(observation.review)

    def test_malformed_iptables_policy_is_reported_for_review(self):
        observation = firewall._parse_iptables_save(
            "*filter\n:INPUT DROP [broken]\nCOMMIT\n",
            implementation="iptables",
        )

        self.assertEqual(observation.state, "ERROR")
        self.assertTrue(observation.review)


class FirewallCollectorTests(unittest.TestCase):
    def test_missing_firewall_tools_does_not_claim_firewall_is_disabled(self):
        with patch("shutil.which", return_value=None):
            snapshot = firewall.collect_firewall_snapshot()

        self.assertEqual(snapshot.observations, ())
        self.assertTrue(snapshot.review)
        self.assertIn("not assessed", " ".join(snapshot.review).lower())

    def test_collects_nftables_ruleset_read_only(self):
        completed = subprocess.CompletedProcess(
            ["/usr/sbin/nft"], 0, '{"nftables": []}', ""
        )

        with (
            patch(
                "shutil.which",
                side_effect=lambda name, path=None: (
                    "/usr/sbin/nft" if name == "nft" else None
                ),
            ),
            patch("subprocess.run", return_value=completed) as run,
        ):
            snapshot = firewall.collect_firewall_snapshot()

        self.assertEqual(len(snapshot.observations), 1)
        self.assertEqual(snapshot.observations[0].implementation, "nftables")
        self.assertEqual(snapshot.observations[0].state, "EMPTY")
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.kwargs["timeout"], 8)

    def test_nftables_command_failure_is_not_reported_as_empty_ruleset(self):
        failed = subprocess.CompletedProcess(
            ["/usr/sbin/nft"], 1, "", "Operation not permitted"
        )

        with (
            patch(
                "shutil.which",
                side_effect=lambda name, path=None: (
                    "/usr/sbin/nft" if name == "nft" else None
                ),
            ),
            patch("subprocess.run", return_value=failed),
        ):
            snapshot = firewall.collect_firewall_snapshot()

        self.assertTrue(snapshot.observations)
        self.assertEqual(snapshot.observations[0].state, "NOT_ASSESSED")
        self.assertTrue(snapshot.review)


    def test_nft_execution_errors_and_timeouts_are_not_reported_as_empty(self):
        command = ["/usr/sbin/nft", "-j", "list", "ruleset"]
        errors = (
            OSError("simulated execution failure"),
            subprocess.TimeoutExpired(command, timeout=8),
        )

        for error in errors:
            with self.subTest(error=type(error).__name__):
                with (
                    patch(
                        "shutil.which",
                        side_effect=lambda name, path=None: (
                            "/usr/sbin/nft" if name == "nft" else None
                        ),
                    ),
                    patch("subprocess.run", side_effect=error),
                ):
                    snapshot = firewall.collect_firewall_snapshot()

                self.assertEqual(len(snapshot.observations), 1)
                observation = snapshot.observations[0]
                self.assertEqual(observation.state, "NOT_ASSESSED")
                self.assertTrue(observation.review)
                self.assertNotEqual(observation.state, "EMPTY")

    def test_iptables_nonzero_exit_is_not_reported_as_empty(self):
        failed = subprocess.CompletedProcess(
            ["/usr/sbin/iptables-save"],
            1,
            "",
            "Operation not permitted",
        )

        with (
            patch(
                "shutil.which",
                side_effect=lambda name, path=None: (
                    "/usr/sbin/iptables-save"
                    if name == "iptables-save"
                    else None
                ),
            ),
            patch("subprocess.run", return_value=failed),
        ):
            snapshot = firewall.collect_firewall_snapshot()

        self.assertEqual(len(snapshot.observations), 1)
        observation = snapshot.observations[0]
        self.assertEqual(observation.implementation, "iptables")
        self.assertEqual(observation.state, "NOT_ASSESSED")
        self.assertTrue(observation.review)

    def test_failed_nft_collection_does_not_hide_iptables_results(self):
        iptables_output = """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
"""

        def available_tool(name, path=None):
            return {
                "nft": "/usr/sbin/nft",
                "iptables-save": "/usr/sbin/iptables-save",
            }.get(name)

        def run_command(command, **kwargs):
            if command[0] == "/usr/sbin/nft":
                return subprocess.CompletedProcess(
                    command, 1, "", "Operation not permitted"
                )

            return subprocess.CompletedProcess(
                command, 0, iptables_output, ""
            )

        with (
            patch("shutil.which", side_effect=available_tool),
            patch("subprocess.run", side_effect=run_command),
        ):
            snapshot = firewall.collect_firewall_snapshot()

        self.assertEqual(
            [item.implementation for item in snapshot.observations],
            ["nftables", "iptables"],
        )
        self.assertEqual(
            [item.state for item in snapshot.observations],
            ["NOT_ASSESSED", "CONFIGURED"],
        )
        self.assertTrue(snapshot.review)
        self.assertTrue(snapshot.observations[1].chains)


class FirewallRuleMetadataTests(unittest.TestCase):
    def test_iptables_preserves_rule_order_and_conditionality(self):
        output = """*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -m comment --comment "default inbound deny" -j DROP
COMMIT
"""
        observation = firewall._parse_iptables_save(
            output, implementation="iptables"
        )
        input_chain = next(
            chain for chain in observation.chains if chain.name == "INPUT"
        )

        self.assertEqual(input_chain.chain_type, "filter")
        self.assertEqual(input_chain.hook, "input")
        self.assertEqual(input_chain.policy, "ACCEPT")
        self.assertEqual(
            [rule.position for rule in input_chain.rules],
            [1, 2, 3],
        )
        self.assertEqual(
            [rule.target for rule in input_chain.rules],
            ["ACCEPT", "ACCEPT", "DROP"],
        )
        self.assertEqual(
            [rule.unconditional for rule in input_chain.rules],
            [False, False, True],
        )

    def test_iptables_detects_a_truly_unconditional_drop(self):
        output = """*filter
:INPUT ACCEPT [0:0]
-A INPUT -j DROP
COMMIT
"""
        observation = firewall._parse_iptables_save(
            output, implementation="iptables"
        )
        input_chain = next(
            chain for chain in observation.chains if chain.name == "INPUT"
        )

        self.assertEqual(len(input_chain.rules), 1)
        self.assertEqual(input_chain.rules[0].target, "DROP")
        self.assertTrue(input_chain.rules[0].unconditional)

    def test_iptables_preserves_return_as_unconditional_verdict(self):
        output = """*filter
:INPUT ACCEPT [0:0]
-A INPUT -j RETURN
COMMIT
"""
        observation = firewall._parse_iptables_save(
            output, implementation="iptables"
        )
        input_chain = next(
            chain for chain in observation.chains if chain.name == "INPUT"
        )

        self.assertEqual(len(input_chain.rules), 1)
        rule = input_chain.rules[0]
        self.assertEqual(rule.target, "RETURN")
        self.assertIsNone(rule.target_chain)
        self.assertTrue(rule.unconditional)

    def test_nft_preserves_filter_chain_type_and_ordered_actions(self):
        payload = {
            "nftables": [
                {"table": {"family": "inet", "name": "filter"}},
                {
                    "chain": {
                        "family": "inet",
                        "table": "filter",
                        "name": "input",
                        "type": "filter",
                        "hook": "input",
                        "prio": 0,
                        "policy": "accept",
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "filter",
                        "chain": "input",
                        "expr": [
                            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
                            {"accept": None},
                        ],
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "filter",
                        "chain": "input",
                        "expr": [{"counter": None}, {"drop": None}],
                    }
                },
            ]
        }
        observation = firewall._parse_nft_json(json.dumps(payload))
        input_chain = next(
            chain for chain in observation.chains if chain.name == "input"
        )

        self.assertEqual(input_chain.chain_type, "filter")
        self.assertEqual(input_chain.hook, "input")
        self.assertEqual(input_chain.policy, "ACCEPT")
        self.assertEqual(
            [rule.target for rule in input_chain.rules],
            ["ACCEPT", "DROP"],
        )
        self.assertFalse(input_chain.rules[0].unconditional)
        self.assertEqual(input_chain.rules[0].conditions, ("meta iifname == 'lo'",))
        self.assertEqual(
            input_chain.rules[0].conditions,
            ("meta iifname == 'lo'",),
        )
        self.assertTrue(input_chain.rules[1].unconditional)

class NftConditionRenderingTests(unittest.TestCase):
    def test_renders_payload_fields_and_connection_state_sets(self):
        expressions = [
            {
                "match": {
                    "op": "==",
                    "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                    "right": "192.168.122.0/24",
                }
            },
            {
                "match": {
                    "op": "in",
                    "left": {"ct": {"key": "state"}},
                    "right": {"set": ["established", "related"]},
                }
            },
        ]

        conditions = firewall._nft_match_conditions(expressions)

        self.assertEqual(
            conditions,
            (
                "payload ip daddr == '192.168.122.0/24'",
                "ct state in {'established', 'related'}",
            ),
        )

    def test_unknown_operand_is_not_rendered_as_a_fake_comparison(self):
        conditions = firewall._nft_match_conditions([
            {
                "match": {
                    "op": "==",
                    "left": {"unknown_operand": {"value": 1}},
                    "right": {"another_unknown": {"value": 2}},
                }
            }
        ])

        self.assertEqual(
            conditions,
            ("nft match condition could not be rendered (operator '==')",),
        )
class NftPrefixOperandTests(unittest.TestCase):
    def test_ipv4_prefix_is_rendered(self):
        from vulpnix.collectors.firewall import _nft_operand_text

        self.assertEqual(
            _nft_operand_text({
                "prefix": {"addr": "192.168.122.0", "len": 24}
            }),
            "192.168.122.0/24",
        )

    def test_invalid_prefix_is_not_rendered(self):
        from vulpnix.collectors.firewall import _nft_operand_text

        self.assertIsNone(
            _nft_operand_text({
                "prefix": {"addr": "192.168.122.0", "len": 33}
            })
        )

