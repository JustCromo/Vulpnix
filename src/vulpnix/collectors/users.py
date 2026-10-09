"""Read local account databases without evaluating their contents."""

from pathlib import Path

from vulpnix.models import User
from vulpnix.parsers.users import parse_local_users

_PASSWD_PATH = Path("/etc/passwd")
_GROUP_PATH = Path("/etc/group")
_SHADOW_PATH = Path("/etc/shadow")


def _read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return None


def collect_local_users(
    passwd_path: Path = _PASSWD_PATH,
    group_path: Path = _GROUP_PATH,
    shadow_path: Path = _SHADOW_PATH,
) -> tuple[User, ...]:
    """Collect local users; inaccessible optional databases remain unknown."""
    passwd_content = passwd_path.read_text(encoding="utf-8")
    group_content = _read_optional(group_path)
    shadow_content = _read_optional(shadow_path)
    return parse_local_users(passwd_content, group_content, shadow_content)
