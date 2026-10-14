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
