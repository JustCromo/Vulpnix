"""Read selected Linux sysctl values without changing kernel configuration."""

from pathlib import Path

from vulpnix.models import SysctlObservation


# Only a fixed allow-list of kernel controls is read. Vulpnix never writes sysctl.
HARDENING_KEYS: tuple[str, ...] = (
    "kernel.dmesg_restrict",
    "kernel.kptr_restrict",
    "kernel.yama.ptrace_scope",
    "fs.protected_hardlinks",
    "fs.protected_symlinks",
    "fs.suid_dumpable",
    "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.all.accept_source_route",
    "net.ipv4.conf.default.accept_source_route",
    "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.all.rp_filter",
    "net.ipv6.conf.all.accept_redirects",
    "net.ipv6.conf.default.accept_redirects",
)



def collect_sysctl_observations(root: str | Path = "/proc/sys") -> tuple[SysctlObservation, ...]:
    """Read the allow-listed sysctl files; record missing or unreadable values."""
    base = Path(root)
    observations: list[SysctlObservation] = []
    for key in HARDENING_KEYS:
        path = base.joinpath(*key.split("."))
        try:
            value = path.read_text(encoding="ascii").strip()
            if not value or any(ch not in "0123456789+-" for ch in value):
                observations.append(SysctlObservation(key, None, "value was empty or malformed"))
            else:
                observations.append(SysctlObservation(key, value))
        except FileNotFoundError:
            observations.append(SysctlObservation(key, None, "parameter is not present on this kernel"))
        except PermissionError:
            observations.append(SysctlObservation(key, None, "permission denied while reading parameter"))
        except (OSError, UnicodeError) as error:
            observations.append(SysctlObservation(key, None, f"could not read parameter ({type(error).__name__})"))
    return tuple(observations)

