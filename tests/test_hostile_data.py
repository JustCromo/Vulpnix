"""Every migrated area must neutralize hostile observed data.

Names of files, services, accounts and processes, command output and error text
can all be chosen by someone else, and Vulpnix often runs as root. These tests
feed escape sequences, forged lines and huge values into each area and check
that nothing unsafe survives into the result or onto the terminal.
"""

import io
from contextlib import redirect_stdout
import unittest
from unittest.mock import patch

from vulpnix.areas.hardening import KernelHardeningArea, area as hardening_area
from vulpnix.areas.host import HostArea, area as host_area
from vulpnix.areas.services import ServicesArea, UnitFilesArea
from vulpnix.areas.services import area as services_area
from vulpnix.areas.services import unit_files as unit_files_area
from vulpnix.areas.ssh import SSHConfigArea, SSHHostKeyArea
from vulpnix.areas.ssh import host_keys as host_keys_area
from vulpnix.areas.users import UsersArea
from vulpnix.areas.users import area as users_area
from vulpnix.cli import app
from vulpnix.collectors.ssh import SSHCommandError
from vulpnix.context import Environment, ExecutionContext
from vulpnix.core.sanitize import MAX_TEXT
from vulpnix.engine import run_area
from vulpnix.models import (
    Service,
    SSHHostKeyObservation,
    SudoGrant,
    SudoPrivilege,
    SudoPrivilegeStatus,
    SysctlObservation,
    SystemInfo,
    UnitFileObservation,
    User,
)
from vulpnix.scan.privilege import PrivilegeContext

ESC = "\x1b"
EVIL = "a\x1b[2Jb\x1b]52;c;aGFjaw==\x07c\nFORGED-LINE-d\r\te"
HUGE = "z" * 100_000
CTX = lambda: ExecutionContext(PrivilegeContext(0, "PRIVILEGED"), Environment.NATIVE)
PAYLOADS = (ESC + "[2J", ESC + "]52", "\x07", "\r")


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from strings(item)
    elif hasattr(value, "__dataclass_fields__"):
        for name in value.__dataclass_fields__:
            yield from strings(getattr(value, name))


def hostile_areas():
    path = "/etc/systemd/system/" + EVIL
    return {
        "host": HostArea(lambda: SystemInfo(EVIL, EVIL, EVIL, EVIL, EVIL, 5.0)),
        "ssh": SSHConfigArea(lambda: (_ for _ in ()).throw(SSHCommandError(2, "", EVIL, option="-G"))),
        "ssh_host_keys": SSHHostKeyArea(lambda: (
            SSHHostKeyObservation("/etc/ssh/ssh_host_" + EVIL + "_key", 1000, 0o644, True, False),
            SSHHostKeyObservation("/etc/ssh/" + EVIL, None, None, None, False, EVIL),
        )),
        "hardening": KernelHardeningArea(lambda: (
            SysctlObservation("kernel.kptr_restrict", EVIL),
            SysctlObservation("kernel.dmesg_restrict", None, EVIL),
        )),
        "users": UsersArea(
            lambda: (User(EVIL, 1000, 1000, (EVIL,), EVIL, None, EVIL),),
            lambda users: (SudoPrivilege(EVIL, SudoPrivilegeStatus.PRIVILEGES_FOUND,
                                         grants=(SudoGrant((EVIL,), (EVIL,), (EVIL,), (EVIL,), EVIL),), host=EVIL),
                           SudoPrivilege("x", SudoPrivilegeStatus.NOT_ASSESSED, reason=EVIL)),
        ),
        "services": ServicesArea(lambda: (Service(EVIL, EVIL, None, None, "systemd", EVIL),)),
        "unit_files": UnitFilesArea(
            lambda services: ((UnitFileObservation(EVIL, path, 1000, 0o666, True, False),
                               UnitFileObservation(EVIL, path + "2", None, None, None, False, EVIL)), (EVIL,)),
            lambda: (Service("a.service"),),
        ),
    }


class HostileDataInResultsTests(unittest.TestCase):
    def test_no_area_lets_control_characters_into_its_result(self):
        for name, area in hostile_areas().items():
            with self.subTest(area=name):
                result = run_area(area, CTX())
                found = list(strings(result))
                self.assertTrue(found)
                for text in found:
                    self.assertTrue(text.isprintable(), f"{name}: {text!r}")

    def test_hostile_data_really_reaches_the_areas(self):
        # Guard against a vacuous test: the unsanitized area output does contain it.
        # The SSH config area already cleans its error text at the source, so it is
        # the one area whose raw output is expected to be safe on its own.
        for name, area in hostile_areas().items():
            if name == "ssh":
                continue
            with self.subTest(area=name):
                raw = area.run(CTX())
                self.assertTrue(any(not text.isprintable() for text in strings(raw)), name)

    def test_huge_values_are_bounded_in_every_area(self):
        areas = {
            "host": HostArea(lambda: SystemInfo(HUGE, HUGE, HUGE, HUGE, HUGE, 1.0)),
            "services": ServicesArea(lambda: (Service(HUGE + ".service", HUGE, None, None, "systemd", HUGE),)),
            "unit_files": UnitFilesArea(
                lambda s: ((UnitFileObservation("a.service", "/etc/systemd/system/" + HUGE, 0, 0o644, True, False),), (HUGE,)),
                lambda: (Service("a.service"),),
            ),
        }
        for name, area in areas.items():
            with self.subTest(area=name):
                result = run_area(area, CTX())
                self.assertLessEqual(max(len(text) for text in strings(result)), MAX_TEXT)


class HostileDataOnTheTerminalTests(unittest.TestCase):
    def capture(self, callback):
        output = io.StringIO()
        with patch.object(app, "terminal_size", return_value=(120, 40)), redirect_stdout(output):
            callback()
        return output.getvalue()

    def assert_clean(self, text, where):
        for payload in PAYLOADS:
            self.assertNotIn(payload, text, f"{where}: {payload!r}")
        self.assertFalse(any(line.lstrip().startswith("FORGED-LINE") for line in text.splitlines()), where)

    def test_host_output_is_clean(self):
        with patch.object(host_area, "collect_system_info", return_value=SystemInfo(EVIL, EVIL, EVIL, EVIL, EVIL, 5.0)):
            self.assert_clean(self.capture(lambda: app._show_host_assessment("HOST DETAILS", details=True)), "host")

    def test_ssh_output_is_clean(self):
        keys = (SSHHostKeyObservation("/etc/ssh/ssh_host_" + EVIL + "_key", 1000, 0o644, True, False),)
        with patch.object(ssh_collect(), "collect_ssh_config", side_effect=SSHCommandError(2, "", EVIL, option="-G")), \
             patch.object(host_keys_area, "collect_ssh_host_key_metadata", return_value=keys):
            self.assert_clean(self.capture(lambda: app._show_ssh_assessment(detailed=True)), "ssh")

    def test_hardening_output_is_clean(self):
        with patch.object(hardening_area, "collect_sysctl_observations", return_value=(SysctlObservation("kernel.kptr_restrict", EVIL),)):
            self.assert_clean(self.capture(lambda: app._dispatch_command("scan hardening --details")), "hardening")

    def test_users_output_is_clean(self):
        users = (User(EVIL, 1000, 1000, (EVIL,), EVIL, None, EVIL),)
        sudo = (SudoPrivilege(EVIL, SudoPrivilegeStatus.PRIVILEGES_FOUND, grants=(SudoGrant((EVIL,), (EVIL,), (EVIL,), (EVIL,), EVIL),), host=EVIL),)
        with patch.object(users_area, "collect_local_users", return_value=users), \
             patch.object(users_area, "collect_sudo_privileges", return_value=sudo):
            self.assert_clean(self.capture(lambda: app._show_users_assessment(detailed=True)), "users")

    def test_services_and_unit_file_output_is_clean(self):
        services = (Service(EVIL + ".service", "active", True, None, "systemd", "enabled"),)
        units = ((UnitFileObservation(EVIL + ".service", "/etc/systemd/system/" + EVIL, 1000, 0o666, True, False),), (EVIL,))
        with patch.object(services_area, "collect_services", return_value=services), \
             patch.object(unit_files_area, "collect_service_unit_file_metadata", return_value=units):
            self.assert_clean(self.capture(lambda: app._show_service_assessment(detailed=True)), "services")


def ssh_collect():
    from vulpnix.areas.ssh import area as ssh_area
    return ssh_area


if __name__ == "__main__":
    unittest.main()
