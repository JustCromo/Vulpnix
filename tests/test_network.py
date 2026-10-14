"""Tests for listening-socket inventory and bind-scope classification."""

import subprocess
import unittest
import json
from unittest.mock import patch

from vulpnix.collectors import network
from vulpnix.models import NetworkSnapshot


class NetworkParserTests(unittest.TestCase):
    def test_parses_tcp_udp_process_and_bind_scope(self):
        output = '\n'.join((
            'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))',
            'tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:* users:(("cupsd",pid=456,fd=7))',
            'udp UNCONN 0 0 [::]:5353 [::]:* users:(("mdns",pid=789,fd=5))',
        ))
        endpoints, malformed = network._parse_ss(output)
        self.assertEqual(malformed, 0)
        by_port = {item.port: item for item in endpoints}
        self.assertEqual(by_port[22].bind_scope, "ALL INTERFACES")
        self.assertEqual(by_port[22].process_name, "sshd")
        self.assertEqual(by_port[631].bind_scope, "LOOPBACK")
        self.assertEqual(by_port[5353].address, "::")
        self.assertEqual(by_port[5353].bind_scope, "ALL INTERFACES")

    def test_malformed_rows_are_counted_instead_of_inventing_data(self):
        endpoints, malformed = network._parse_ss("not an ss row\ntcp LISTEN 0 1 malformed")
        self.assertEqual(endpoints, ())
        self.assertEqual(malformed, 2)

    def test_ipv4_and_ipv6_proc_address_decoding(self):
        self.assertEqual(network._decode_proc_address("0100007F", ipv6=False), "127.0.0.1")
        self.assertEqual(network._decode_proc_address("00000000000000000000000001000000", ipv6=True), "::1")


class NetworkCollectorTests(unittest.TestCase):
    def test_rootless_inventory_is_marked_partial_when_processes_are_present(self):
        output = 'tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))'
        completed = subprocess.CompletedProcess(["ss"], 0, output, "")
        with patch.object(network.shutil, "which", return_value="/usr/bin/ss"), patch.object(network.subprocess, "run", return_value=completed) as run:
            snapshot = network.collect_network_snapshot(privileged=False)
        self.assertEqual(len(snapshot.endpoints), 1)
        self.assertFalse(snapshot.process_attribution_complete)
        self.assertTrue(snapshot.review)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.kwargs["timeout"], 8)

    def test_missing_ss_falls_back_to_procfs(self):
        expected = NetworkSnapshot((), "/proc/net", False, ())
        with patch.object(network.shutil, "which", return_value=None), patch.object(network, "_collect_procfs", return_value=expected):
            self.assertIs(network.collect_network_snapshot(privileged=True), expected)

    def test_failed_ss_uses_procfs_fallback_when_available(self):
        failed = subprocess.CompletedProcess(["ss"], 1, "", "unsupported")
        fallback = NetworkSnapshot((), "/proc/net", False, ())
        with patch.object(network.shutil, "which", return_value="/usr/bin/ss"), patch.object(network.subprocess, "run", return_value=failed):
            with patch.object(network, "_collect_procfs", return_value=fallback):
                snapshot = network.collect_network_snapshot(privileged=True)
        self.assertEqual(snapshot.source, "/proc/net")
        self.assertFalse(snapshot.process_attribution_complete)
        self.assertTrue(any("ss failed" in message for message in snapshot.review))

    def test_failed_ss_commands_raise_instead_of_returning_empty_inventory(self):
        failed = subprocess.CompletedProcess(["ss"], 1, "", "unsupported")
        with patch.object(network.shutil, "which", return_value="/usr/bin/ss"), patch.object(network.subprocess, "run", return_value=failed):
            with patch.object(network, "_collect_procfs", side_effect=OSError("procfs unavailable")):
                with self.assertRaises(subprocess.CalledProcessError):
                    network.collect_network_snapshot(privileged=True)

class NetworkInterfaceParserTests(unittest.TestCase):
    def test_parses_interface_state_and_ipv4_ipv6_addresses(self):
        output = json.dumps([
            {
                "ifindex": 2,
                "ifname": "enp1s0",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "operstate": "UP",
                "addr_info": [
                    {
                        "family": "inet",
                        "local": "192.0.2.10",
                        "prefixlen": 24,
                    },
                    {
                        "family": "inet6",
                        "local": "2001:db8::10",
                        "prefixlen": 64,
                    },
                ],
            }
        ])

        interfaces, malformed = network._parse_ip_address(output)

        self.assertEqual(malformed, 0)
        self.assertEqual(len(interfaces), 1)

        interface = interfaces[0]
        self.assertEqual(interface.name, "enp1s0")
        self.assertEqual(interface.state, "UP")
        self.assertEqual(
            interface.flags,
            ("BROADCAST", "MULTICAST", "UP", "LOWER_UP"),
        )
        self.assertEqual(
            interface.addresses,
            ("192.0.2.10/24", "2001:db8::10/64"),
        )

    def test_invalid_json_and_non_list_payload_are_rejected(self):
        self.assertEqual(network._parse_ip_address("{"), ((), 1))
        self.assertEqual(
            network._parse_ip_address('{"ifname":"enp1s0"}'),
            ((), 1),
        )

    def test_malformed_family_type_does_not_crash_parser(self):
        output = json.dumps([
            {
                "ifname": "test0",
                "operstate": "UP",
                "flags": [],
                "addr_info": [
                    {
                        "family": [],
                        "local": "192.0.2.1",
                        "prefixlen": 24,
                    }
                ],
            }
        ])

        interfaces, malformed = network._parse_ip_address(output)

        self.assertEqual(malformed, 1)
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0].addresses, ())

class NetworkInterfaceCollectorTests(unittest.TestCase):
    def test_collects_interfaces_using_ip_json(self):
        output = json.dumps([
            {
                "ifname": "enp1s0",
                "flags": ["UP", "LOWER_UP"],
                "operstate": "UP",
                "addr_info": [
                    {
                        "family": "inet",
                        "local": "192.0.2.10",
                        "prefixlen": 24,
                    }
                ],
            }
        ])
        completed = subprocess.CompletedProcess(
            ["ip"], 0, output, ""
        )

        with (
            patch.object(
                network.shutil, "which", return_value="/usr/bin/ip"
            ),
            patch.object(
                network.subprocess, "run", return_value=completed
            ) as run,
        ):
            snapshot = network.collect_network_interfaces()

        self.assertEqual(len(snapshot.interfaces), 1)
        self.assertEqual(snapshot.interfaces[0].name, "enp1s0")
        self.assertEqual(
            snapshot.interfaces[0].addresses,
            ("192.0.2.10/24",),
        )
        self.assertFalse(snapshot.review)
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/bin/ip", "-j", "address", "show"],
        )
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_missing_ip_marks_interface_inventory_unassessed(self):
        with patch.object(network.shutil, "which", return_value=None):
            snapshot = network.collect_network_interfaces()

        self.assertEqual(snapshot.interfaces, ())
        self.assertEqual(snapshot.source, "unavailable")
        self.assertTrue(snapshot.review)
        self.assertTrue(
            any("not assessed" in item for item in snapshot.review)
        )

    def test_failed_ip_command_marks_inventory_unassessed(self):
        completed = subprocess.CompletedProcess(
            ["/usr/bin/ip"], 1, "", "permission denied"
        )

        with (
            patch.object(
                network.shutil, "which", return_value="/usr/bin/ip"
            ),
            patch.object(
                network.subprocess, "run", return_value=completed
            ),
        ):
            snapshot = network.collect_network_interfaces()

        self.assertEqual(snapshot.interfaces, ())
        self.assertTrue(snapshot.review)
        self.assertTrue(
            any("not assessed" in item for item in snapshot.review)
        )
