"""Tests for listening-socket inventory and bind-scope classification."""

import subprocess
import unittest
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
