"""Read-only listening-socket inventory using ss, with a procfs fallback."""

import ipaddress
import os
from pathlib import Path
import re
import shutil
import subprocess
import json

from vulpnix.models import(
    ListeningEndpoint,
    NetworkInterface,
    NetworkInterfaceSnapshot,
    NetworkSnapshot,

)

_OWNER_RE = re.compile(r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>[0-9]+)')
_SS_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def _parse_endpoint(token: str) -> tuple[str, int | None]:
    token = token.strip()
    if token.startswith("[") and "]:" in token:
        address, raw_port = token[1:].rsplit("]:", 1)
    elif ":" in token:
        address, raw_port = token.rsplit(":", 1)
    else:
        return token, None
    if raw_port.isdigit():
        port = int(raw_port, 10)
        if 0 <= port <= 65535:
            return address, port
    return address, None


def _binding_scope(address: str) -> str:
    if address in {"*", "0.0.0.0", "::", "[::]"}:
        return "ALL INTERFACES"
    normalized = address.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        return "UNKNOWN"
    return "LOOPBACK" if parsed.is_loopback else "NON-LOOPBACK"


def _parse_ss(output: str) -> tuple[tuple[ListeningEndpoint, ...], int]:
    endpoints: list[ListeningEndpoint] = []
    malformed = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split(maxsplit=6)
        if len(fields) < 5:
            malformed += 1
            continue
        protocol, state = fields[0].lower(), fields[1].upper()
        if protocol not in {"tcp", "tcp6", "udp", "udp6"}:
            continue
        address, port = _parse_endpoint(fields[4])
        if port is None:
            malformed += 1
            continue
        tail = " ".join(fields[6:]) if len(fields) > 6 else ""
        owner = _OWNER_RE.search(tail)
        endpoints.append(ListeningEndpoint(
            protocol=protocol,
            state=state,
            address=address,
            port=port,
            bind_scope=_binding_scope(address),
            process_name=owner.group("name") if owner else None,
            pid=int(owner.group("pid")) if owner else None,
        ))
    endpoints.sort(key=lambda item: (item.protocol, item.port or 0, item.address, item.state))
    return tuple(endpoints), malformed

def _parse_ip_address(
    output: str,
) -> tuple[tuple[NetworkInterface, ...], int]:
    """Parse `ip -j address show` output without inventing missing data."""
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return (), 1

    if not isinstance(payload, list):
        return (), 1

    interfaces: list[NetworkInterface] = []
    malformed = 0

    for entry in payload:
        if not isinstance(entry, dict):
            malformed += 1
            continue

        name = entry.get("ifname")
        if not isinstance(name, str) or not name.strip():
            malformed += 1
            continue

        state = entry.get("operstate")
        if not isinstance(state, str) or not state.strip():
            state = "NOT_ASSESSED"

        raw_flags = entry.get("flags", [])
        if (
            not isinstance(raw_flags, list)
            or any(not isinstance(flag, str) for flag in raw_flags)
        ):
            malformed += 1
            flags: tuple[str, ...] = ()
        else:
            flags = tuple(raw_flags)

        raw_addresses = entry.get("addr_info", [])
        if not isinstance(raw_addresses, list):
            malformed += 1
            raw_addresses = []

        addresses: set[str] = set()

        for item in raw_addresses:
            if not isinstance(item, dict):
                malformed += 1
                continue

            family = item.get("family")
            if not isinstance(family, str):
                malformed += 1
                continue

            if family not in {"inet", "inet6"}:
                continue

            local = item.get("local")
            prefix = item.get("prefixlen")

            if (
                not isinstance(local, str)
                or not isinstance(prefix, int)
                or isinstance(prefix, bool)
            ):
                malformed += 1
                continue

            try:
                parsed = ipaddress.ip_address(local)
                max_prefix = parsed.max_prefixlen

                if (
                    (family == "inet" and parsed.version != 4)
                    or (family == "inet6" and parsed.version != 6)
                    or not 0 <= prefix <= max_prefix
                ):
                    raise ValueError("invalid address or prefix")
            except ValueError:
                malformed += 1
                continue

            addresses.add(f"{parsed}/{prefix}")

        interfaces.append(
            NetworkInterface(
                name=name,
                state=state.upper(),
                flags=flags,
                addresses=tuple(sorted(addresses)),
            )
        )

    interfaces.sort(key=lambda item: item.name)
    return tuple(interfaces), malformed


def _decode_proc_address(raw: str, *, ipv6: bool) -> str:
    raw_bytes = bytes.fromhex(raw)
    if ipv6:
        # procfs prints each 32-bit IPv6 word in host byte order on Linux.
        raw_bytes = b"".join(raw_bytes[index:index + 4][::-1] for index in range(0, 16, 4))
    else:
        raw_bytes = raw_bytes[::-1]
    return str(ipaddress.ip_address(raw_bytes))


def _collect_procfs(proc_net: str | Path = "/proc/net") -> NetworkSnapshot:
    base = Path(proc_net)
    endpoints: list[ListeningEndpoint] = []
    errors: list[str] = []
    files = (("tcp", "tcp", True, False), ("tcp6", "tcp", True, True), ("udp", "udp", False, False), ("udp6", "udp", False, True))
    readable_files = 0
    for filename, protocol, only_listening, ipv6 in files:
        try:
            lines = (base / filename).read_text(encoding="ascii").splitlines()
            readable_files += 1
        except FileNotFoundError:
            # IPv6 proc entries may be absent if IPv6 is not supported/enabled.
            if ipv6:
                continue
            errors.append(f"/proc/net/{filename} is missing")
            continue
        except (OSError, UnicodeError):
            errors.append(f"/proc/net/{filename} could not be read")
            continue
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10:
                errors.append(f"malformed entry in /proc/net/{filename}")
                continue
            state = fields[3]
            if only_listening and state != "0A":
                continue
            try:
                raw_address, raw_port = fields[1].split(":", 1)
                address = _decode_proc_address(raw_address, ipv6=ipv6)
                port = int(raw_port, 16)
                if not 0 <= port <= 65535:
                    raise ValueError("invalid port")
            except (ValueError, OverflowError):
                errors.append(f"malformed endpoint in /proc/net/{filename}")
                continue
            endpoints.append(ListeningEndpoint(
                protocol=protocol,
                state="LISTEN" if protocol == "tcp" else "BOUND",
                address=address,
                port=port,
                bind_scope=_binding_scope(address),
            ))
    if readable_files == 0:
        raise OSError("procfs socket tables could not be read")
    endpoints.sort(key=lambda item: (item.protocol, item.port or 0, item.address, item.state))
    return NetworkSnapshot(
        endpoints=tuple(endpoints),
        source="/proc/net",
        process_attribution_complete=False,
        review=tuple(dict.fromkeys(errors)),
    )


def collect_network_snapshot(*, privileged: bool | None = None) -> NetworkSnapshot:
    """Collect listening/bound local sockets; process ownership is best-effort and read-only."""
    if privileged is None:
        privileged = os.geteuid() == 0
    ss = shutil.which("ss", path=_SS_PATH)
    if ss is None:
        return _collect_procfs()

    result = subprocess.run(
        [ss, "-H", "-lntup"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=8,
        shell=False,
        env={"PATH": _SS_PATH, "LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
    )
    source = "ss -lntup"
    if result.returncode != 0:
        # Keep useful socket visibility if this ss implementation does not support -p.
        fallback = subprocess.run(
            [ss, "-H", "-lntu"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            shell=False,
            env={"PATH": _SS_PATH, "LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
        )
        if fallback.returncode != 0:
            # If ss is unusable, keep socket visibility via procfs when possible.
            # This fallback cannot reliably associate sockets with processes.
            try:
                snapshot = _collect_procfs()
            except OSError:
                raise subprocess.CalledProcessError(
                    fallback.returncode,
                    [ss, "-H", "-lntu"],
                    output=fallback.stdout,
                    stderr=fallback.stderr,
                )
            note = "ss failed; using procfs fallback without process attribution"
            return NetworkSnapshot(
                endpoints=snapshot.endpoints,
                source=snapshot.source,
                process_attribution_complete=False,
                review=tuple(dict.fromkeys((*snapshot.review, note))),
            )
        result = fallback
        source = "ss -lntu"

    endpoints, malformed = _parse_ss(result.stdout)
    review: list[str] = []
    if malformed:
        review.append(f"{malformed} socket row(s) could not be parsed")
    if not privileged and endpoints:
        review.append("process ownership may be incomplete without elevated privileges")
    elif any(item.process_name is None for item in endpoints) and source == "ss -lntup":
        review.append("ss did not report a process owner for every socket")
    process_complete = privileged and source == "ss -lntup" and not any(item.process_name is None for item in endpoints)
    return NetworkSnapshot(
        endpoints=endpoints,
        source=source,
        process_attribution_complete=process_complete,
        review=tuple(review),
    )

def collect_network_interfaces() -> NetworkInterfaceSnapshot:
    """Collect network interfaces, addresses and operational states."""
    ip_path = shutil.which("ip", path=_SS_PATH)

    if ip_path is None:
        return NetworkInterfaceSnapshot(
            interfaces=(),
            source="unavailable",
            review=(
                "ip command unavailable; interface addresses and "
                "operational states were not assessed",
            ),
        )

    source = "ip -j address show"

    try:
        result = subprocess.run(
            [ip_path, "-j", "address", "show"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8,
            shell=False,
            env={
                "PATH": _SS_PATH,
                "LANG": "C",
                "LC_ALL": "C",
                "SYSTEMD_COLORS": "0",
            },
        )
    except (OSError, subprocess.TimeoutExpired):
        return NetworkInterfaceSnapshot(
            interfaces=(),
            source=source,
            review=(
                "ip command could not complete; interface inventory "
                "was not assessed",
            ),
        )

    if result.returncode != 0:
        return NetworkInterfaceSnapshot(
            interfaces=(),
            source=source,
            review=(
                f"ip command failed with exit status {result.returncode}; "
                "interface inventory was not assessed",
            ),
        )

    interfaces, malformed = _parse_ip_address(result.stdout)
    review = []

    if malformed:
        review.append(
            f"{malformed} interface or address record(s) could not be parsed"
        )

    return NetworkInterfaceSnapshot(
        interfaces=interfaces,
        source=source,
        review=tuple(review),
    )
