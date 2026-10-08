"""Read-only systemd service collection."""

import subprocess

from vulpnix.models import Service
from vulpnix.parsers.systemd import enabled_value, parse_loaded_services, parse_unit_file_states


def _run_systemctl(*arguments: str) -> str:
    """Run a fixed, read-only systemctl query without invoking a shell."""
    result = subprocess.run(
        ["/usr/bin/systemctl", "--system", *arguments],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=10,
        shell=False,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "SYSTEMD_COLORS": "0",
            "SYSTEMD_PAGER": "",
        },
    )
    return result.stdout


def collect_services() -> tuple[Service, ...]:
    """Collect systemd service state and enablement metadata.

    Command and access failures propagate to the caller; they are not reported
    as an empty service list. PID collection is not part of this first version.
    """
    loaded_output = _run_systemctl(
        "list-units",
        "--type=service",
        "--all",
        "--no-legend",
        "--no-pager",
        "--plain",
    )
    unit_file_output = _run_systemctl(
        "list-unit-files",
        "--type=service",
        "--no-legend",
        "--no-pager",
    )
    loaded_states = parse_loaded_services(loaded_output)
    unit_file_states = parse_unit_file_states(unit_file_output)

    names = sorted(loaded_states.keys() | unit_file_states.keys())
    return tuple(
        Service(
            name=name,
            state=loaded_states.get(name),
            enabled=enabled_value(unit_file_states.get(name)),
            source="systemd",
            unit_file_state=unit_file_states.get(name),
        )
        for name in names
    )
