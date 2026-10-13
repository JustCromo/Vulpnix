"""Deterministic fixtures shared by CLI integration tests."""

from vulpnix.collectors.hardening import HARDENING_KEYS
from vulpnix.models import (
    CoverageStatus,
    FilesystemCoverage,
    NetworkSnapshot,
    SSHHostKeyObservation,
    SysctlObservation,
)


def safe_sysctl_observations():
    values = {
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
    return tuple(SysctlObservation(key, values[key]) for key in HARDENING_KEYS)


def empty_network_snapshot():
    return NetworkSnapshot((), "test fixture", True, ())


def safe_ssh_host_keys():
    return (SSHHostKeyObservation("/etc/ssh/ssh_host_ed25519_key", 0, 0o600, True, False),)


def empty_filesystem_coverage():
    return FilesystemCoverage((), CoverageStatus.COLLECTED, ("/usr",), 0, 0.0, ())

from contextlib import contextmanager, ExitStack
from unittest.mock import patch


@contextmanager
def patch_supplementary_collectors(app_module):
    """Prevent integration tests from touching the real host during full scans."""
    with ExitStack() as stack:
        stack.enter_context(patch.object(app_module, "collect_sysctl_observations", lambda: safe_sysctl_observations()))
        stack.enter_context(patch.object(app_module, "collect_network_snapshot", lambda: empty_network_snapshot()))
        stack.enter_context(patch.object(app_module, "collect_ssh_host_key_metadata", lambda: safe_ssh_host_keys()))
        stack.enter_context(patch.object(app_module, "collect_service_unit_file_metadata", lambda services: ((), ("fixture has no unit-file metadata",))))
        stack.enter_context(patch.object(app_module, "collect_setid_files", lambda: empty_filesystem_coverage()))
        yield
