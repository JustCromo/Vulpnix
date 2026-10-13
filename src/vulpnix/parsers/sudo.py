"""Strict parser for common non-interactive ``sudo -n -l`` output."""

import re

from vulpnix.models import (
    SudoGrant,
    SudoPrivilege,
    SudoPrivilegeStatus,
)

_HEADER = re.compile(
    r"^\s*User\s+(?P<account>\S+)\s+may\s+run\s+(?:the\s+)?following\s+"
    r"commands\s+on\s+(?P<host>.+?):\s*$",
    re.IGNORECASE,
)
_DENIED = re.compile(
    r"^\s*(?:sudo:\s*)?(?:Sorry,\s*)?User\s+(?P<account>\S+)\s+"
    r"(?:is\s+not\s+allowed\s+to\s+run\s+sudo|may\s+not\s+run\s+sudo)\s+"
    r"on\s+(?P<host>.+?)\.?\s*$",
    re.IGNORECASE,
)
_INSPECT_DENIED = re.compile(
    r"\b(?:not\s+allowed|not\s+permitted|may\s+not)\s+to\s+list\s+"
    r"(?:the\s+)?(?:other\s+)?(?:user'?s?\s+)?privileges\b",
    re.IGNORECASE,
)
_PASSWORD_REQUIRED = re.compile(
    r"(?:a\s+)?password\s+is\s+required|authentication\s+is\s+required|"
    r"a\s+terminal\s+is\s+required",
    re.IGNORECASE,
)
_ENVIRONMENT_BLOCKED = re.compile(
    r"\bno\s+new\s+privileges\b|\bno_new_privs\b|"
    r"\bsudo(?:ers)?(?:\.conf)?\s+is\s+owned\s+by\s+uid\s+\d+",
    re.IGNORECASE,
)
_GRANT = re.compile(r"^\s*\((?P<runas>[^()]*)\)\s+(?P<body>\S.*)\s*$")
_OPTION = re.compile(r"^(?P<option>[A-Za-z][A-Za-z0-9_-]*):\s*(?P<rest>.*)$")


def _has_unsafe_controls(value: str) -> bool:
    return any(
        not character.isprintable() and character not in "\r\n\t"
        for character in value
    )


def _diagnostic(stderr: str, stdout: str) -> str | None:
    value = (stderr.strip() or stdout.strip()).replace("\r", "")
    if not value:
        return None
    return "".join(character if character.isprintable() else "�" for character in value)


def _split_values(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _split_commands(value: str) -> tuple[str, ...]:
    commands: list[str] = []
    current: list[str] = []
    escaped = False
    quoted = False
    for character in value:
        if escaped:
            if character not in {",", '"', "\\"}:
                current.append("\\")
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
            current.append(character)
        elif character == "," and not quoted:
            command = "".join(current).strip()
            if not command:
                raise ValueError("empty command in sudo listing")
            commands.append(command)
            current.clear()
        else:
            current.append(character)
    if escaped or quoted:
        raise ValueError("incomplete command in sudo listing")
    command = "".join(current).strip()
    if not command:
        raise ValueError("empty command in sudo listing")
    commands.append(command)
    return tuple(commands)


def _parse_grant(line: str) -> SudoGrant:
    match = _GRANT.match(line)
    if match is None:
        raise ValueError("unrecognized sudo grant line")
    runas = match.group("runas").strip()
    if not runas:
        raise ValueError("missing run-as target in sudo grant")

    body = match.group("body").strip()
    options: list[str] = []
    while True:
        option_match = _OPTION.match(body)
        if option_match is None:
            break
        options.append(option_match.group("option").upper())
        body = option_match.group("rest").strip()
    if not body:
        raise ValueError("missing command in sudo grant")

    target_user_spec, separator, target_group_spec = runas.partition(":")
    return SudoGrant(
        target_users=_split_values(target_user_spec),
        target_groups=_split_values(target_group_spec) if separator else None,
        allowed_commands=_split_commands(body),
        options=tuple(options),
    )


def parse_sudo_listing(
    account: str,
    stdout: str,
    stderr: str = "",
    returncode: int = 0,
) -> SudoPrivilege:
    """Normalize recognized sudo output; retain uncertainty as NOT_ASSESSED."""
    diagnostic = _diagnostic(stderr, stdout)
    combined = f"{stdout}\n{stderr}"

    if _has_unsafe_controls(stdout) or _has_unsafe_controls(stderr):
        return SudoPrivilege(
            account,
            SudoPrivilegeStatus.NOT_ASSESSED,
            reason="sudo returned terminal control characters",
            diagnostic=diagnostic,
        )

    if returncode == 0:
        denied = next(
            (
                match
                for line in combined.splitlines()
                if (match := _DENIED.match(line))
            ),
            None,
        )
        if denied is not None and denied.group("account") == account:
            return SudoPrivilege(
                account,
                SudoPrivilegeStatus.NO_PRIVILEGES,
                host=denied.group("host").rstrip("."),
                reason="sudo explicitly reported no allowed commands",
                diagnostic=diagnostic,
            )

    if returncode != 0:
        if _PASSWORD_REQUIRED.search(combined):
            reason = "non-interactive listing requires authentication"
        elif _INSPECT_DENIED.search(combined):
            reason = "permission denied while inspecting another account"
        elif _ENVIRONMENT_BLOCKED.search(combined):
            reason = "sudo execution blocked by environment or runtime configuration"
        else:
            denied = next(
                (match for line in combined.splitlines() if (match := _DENIED.match(line))),
                None,
            )
            if denied is not None and denied.group("account") == account:
                return SudoPrivilege(
                    account,
                    SudoPrivilegeStatus.NO_PRIVILEGES,
                    host=denied.group("host").rstrip("."),
                    reason="sudo explicitly reported no allowed commands",
                    diagnostic=diagnostic,
                )
            reason = "sudo privilege state could not be established"
        return SudoPrivilege(
            account,
            SudoPrivilegeStatus.NOT_ASSESSED,
            reason=reason,
            diagnostic=diagnostic,
        )

    header: re.Match[str] | None = None
    lines = stdout.splitlines()
    header_index = -1
    for index, line in enumerate(lines):
        match = _HEADER.match(line)
        if match:
            header = match
            header_index = index
            break

    if header is None or header.group("account") != account:
        return SudoPrivilege(
            account,
            SudoPrivilegeStatus.NOT_ASSESSED,
            reason="sudo output did not contain a recognized account listing",
            diagnostic=diagnostic,
        )

    try:
        grant_lines = [line for line in lines[header_index + 1 :] if line.strip()]
        if not grant_lines:
            raise ValueError("sudo listing contained no command grants")
        grants = tuple(_parse_grant(line) for line in grant_lines)
    except ValueError as error:
        return SudoPrivilege(
            account,
            SudoPrivilegeStatus.NOT_ASSESSED,
            host=header.group("host").strip(),
            reason=f"sudo output could not be safely parsed: {error}",
            diagnostic=diagnostic,
        )

    return SudoPrivilege(
        account,
        SudoPrivilegeStatus.PRIVILEGES_FOUND,
        grants=grants,
        host=header.group("host").strip(),
    )
