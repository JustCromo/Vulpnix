from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True, slots=True)
class PrivilegeContext:
    """Privilege state inherited by the whole Vulpnix process."""

    uid: int
    mode: str

    @property
    def privileged(self) -> bool:
        return self.uid == 0


def current_privilege_context() -> PrivilegeContext:
    """Return the UID and privilege mode used by the running Vulpnix process."""
    uid = os.geteuid()
    return PrivilegeContext(uid=uid, mode="PRIVILEGED" if uid == 0 else "ROOTLESS")
