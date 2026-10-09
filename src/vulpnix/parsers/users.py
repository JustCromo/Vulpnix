"""Parsers for local passwd, group, and shadow database records."""

from vulpnix.models import User


def _records(content: str, expected_fields: int, kind: str) -> list[list[str]]:
    records: list[list[str]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) < expected_fields or (kind != "shadow" and len(fields) != expected_fields):
            raise ValueError(f"Malformed {kind} record on line {line_number}")
        if any(field and not field.isprintable() for field in fields):
            raise ValueError(f"Control character in {kind} record on line {line_number}")
        records.append(fields)
    return records


def _nonnegative_id(value: str, kind: str, line_number: int) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise ValueError(f"Invalid {kind} on line {line_number}") from error
    if parsed < 0:
        raise ValueError(f"Invalid {kind} on line {line_number}")
    return parsed


def parse_local_users(
    passwd_content: str,
    group_content: str | None,
    shadow_content: str | None = None,
) -> tuple[User, ...]:
    """Normalize local account/group records without retaining password data."""
    passwd_records = _records(passwd_content, 7, "passwd")
    group_records = _records(group_content, 4, "group") if group_content is not None else None
    shadow_records = _records(shadow_content, 2, "shadow") if shadow_content is not None else None

    groups_by_gid: dict[int, list[str]] = {}
    members_by_user: dict[str, list[str]] = {}
    if group_records is not None:
        names: set[str] = set()
        for line_number, fields in enumerate(group_records, start=1):
            name, _password_placeholder, gid_text, members = fields
            if not name or name in names:
                raise ValueError(f"Invalid or duplicate group name on record {line_number}")
            names.add(name)
            gid = _nonnegative_id(gid_text, "group GID", line_number)
            groups_by_gid.setdefault(gid, []).append(name)
            for username in filter(None, members.split(",")):
                members_by_user.setdefault(username, []).append(name)

    shadow_state: dict[str, str] = {}
    if shadow_records is not None:
        for line_number, fields in enumerate(shadow_records, start=1):
            username, password_field = fields[:2]
            if not username or username in shadow_state:
                raise ValueError(f"Invalid or duplicate shadow user on record {line_number}")
            if not password_field:
                state = "password field empty"
            elif password_field.startswith(("!", "*")):
                state = "password locked"
            else:
                # A stored hash alone does not establish that the account can log in.
                state = ""
            shadow_state[username] = state

    users: list[User] = []
    seen_usernames: set[str] = set()
    for line_number, fields in enumerate(passwd_records, start=1):
        username, _password_placeholder, uid_text, gid_text, _gecos, _home, shell = fields
        if not username or username in seen_usernames:
            raise ValueError(f"Invalid or duplicate username on record {line_number}")
        seen_usernames.add(username)
        uid = _nonnegative_id(uid_text, "UID", line_number)
        gid = _nonnegative_id(gid_text, "GID", line_number)

        if group_records is None or gid not in groups_by_gid:
            groups = None
        else:
            memberships = []
            memberships.extend(groups_by_gid.get(gid, ()))
            memberships.extend(members_by_user.get(username, ()))
            groups = tuple(dict.fromkeys(memberships))

        users.append(
            User(
                username=username,
                uid=uid,
                gid=gid,
                groups=groups,
                shell=shell or None,
                privileged=True if uid == 0 else None,
                account_state=shadow_state.get(username) or None,
            )
        )
    return tuple(users)
