"""Parsers for systemd command output."""

# Valid unit-file states that describe how a unit is enabled, but do not map
# to a boolean enabled/disabled value.
UNIT_FILE_NON_BOOLEAN_STATES = frozenset({
    "static",
    "indirect",
    "generated",
    "transient",
    "alias",
    "linked",
    "linked-runtime",
})


def parse_loaded_services(output: str) -> dict[str, str]:
    """Parse service names and active states from systemctl's unit list."""
    services: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split(maxsplit=4)
        if not fields or not fields[0].endswith(".service"):
            continue
        if len(fields) < 4:
            raise ValueError("Unexpected systemctl list-units output")
        services[fields[0]] = fields[2]
    return services


def parse_unit_file_states(output: str) -> dict[str, str]:
    """Parse installed service unit-file states from systemctl output."""
    states: dict[str, str] = {}
    for line in output.splitlines():
        fields = line.split()
        if not fields or not fields[0].endswith(".service"):
            continue
        if len(fields) < 2:
            raise ValueError("Unexpected systemctl list-unit-files output")
        states[fields[0]] = fields[1]
    return states


def enabled_value(unit_file_state: str | None) -> bool | None:
    if unit_file_state in {"enabled", "enabled-runtime"}:
        return True
    if unit_file_state in {"disabled", "masked", "masked-runtime"}:
        return False
    return None
