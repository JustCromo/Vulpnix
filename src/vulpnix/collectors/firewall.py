"""Read-only firewall discovery and configuration inventory."""

import json
import re
import shutil
import subprocess

from vulpnix.models import FirewallObservation, FirewallSnapshot


def _parse_nft_json(output: str) -> FirewallObservation:
    """Normalize nftables JSON without treating rule presence as a verdict."""
    source = "nft -j list ruleset"

    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return FirewallObservation(
            implementation="nftables",
            state="ERROR",
            source=source,
            summary="The nftables output was not valid JSON.",
            review=("nftables configuration could not be assessed reliably",),
        )

    if not isinstance(payload, dict) or not isinstance(payload.get("nftables"), list):
        return FirewallObservation(
            implementation="nftables",
            state="ERROR",
            source=source,
            summary="The nftables JSON did not have the expected structure.",
            review=("nftables configuration could not be assessed reliably",),
        )

    tables = 0
    chains = 0
    rules = 0
    families: set[str] = set()

    for entry in payload["nftables"]:
        if not isinstance(entry, dict):
            continue

        for kind in ("table", "chain", "rule"):
            item = entry.get(kind)
            if not isinstance(item, dict):
                continue

            family = item.get("family")
            if isinstance(family, str) and family:
                families.add(family)

            if kind == "table":
                tables += 1
            elif kind == "chain":
                chains += 1
            else:
                rules += 1

    details = (
        f"tables={tables}",
        f"chains={chains}",
        f"rules={rules}",
        "families=" + (",".join(sorted(families)) if families else "none"),
    )

    if tables == 0 and chains == 0 and rules == 0:
        state = "EMPTY"
        summary = (
            "The nftables ruleset is empty; this is not a security verdict."
        )
    else:
        state = "CONFIGURED"
        summary = (
            "The nftables ruleset was collected; rule presence alone "
            "does not prove effective protection."
        )

    return FirewallObservation(
        implementation="nftables",
        state=state,
        source=source,
        summary=summary,
        details=details,
    )


def _parse_iptables_save(
    output: str, *, implementation: str
) -> FirewallObservation:
    """Normalize iptables-save output, including default chain policies."""
    if implementation == "iptables":
        family = "ipv4"
        source = "iptables-save"
    elif implementation == "ip6tables":
        family = "ipv6"
        source = "ip6tables-save"
    else:
        family = "unknown"
        source = f"{implementation}-save"

    tables: set[str] = set()
    chains: set[tuple[str, str]] = set()
    policies: dict[tuple[str, str], str] = {}
    rules = 0
    current_table: str | None = None
    malformed = 0

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("*"):
            table_name = line[1:].strip()
            if not table_name:
                malformed += 1
                current_table = None
                continue
            current_table = table_name
            tables.add(table_name)
            continue

        if line == "COMMIT":
            current_table = None
            continue

        if line.startswith(":"):
            if current_table is None:
                malformed += 1
                continue

            match = re.fullmatch(
                r":(\S+)\s+(\S+)\s+\[\d+:\d+\]", line
            )
            if match is None:
                malformed += 1
                continue

            chain_name, policy = match.groups()
            chains.add((current_table, chain_name))

            if policy != "-":
                policies[(current_table, chain_name)] = policy.upper()
            continue

        if line.startswith("-A "):
            if current_table is None:
                malformed += 1
                continue
            rules += 1

    details = [
        f"tables={len(tables)}",
        f"chains={len(chains)}",
        f"rules={rules}",
        f"families={family}",
    ]

    for (table_name, chain_name), policy in sorted(policies.items()):
        details.append(f"{chain_name}={policy}")

    review = ()
    if malformed:
        review = (
            f"{malformed} iptables-save line(s) could not be interpreted",
        )

    if malformed and not chains and rules == 0:
        state = "ERROR"
        summary = (
            f"The {family} output contained no usable chain or rule data; "
            "configuration could not be assessed reliably."
        )
    elif not tables and not chains and rules == 0:
        state = "EMPTY"
        summary = (
            f"No usable {family} ruleset entries were collected; "
            "this is not a security verdict."
        )
    else:
        state = "CONFIGURED"
        summary = (
            f"The {family} ruleset was collected; configured policies and "
            "rules alone do not prove effective protection."
        )

    return FirewallObservation(
        implementation=implementation,
        state=state,
        source=source,
        summary=summary,
        details=tuple(details),
        review=review,
    )

_FIREWALL_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


def collect_firewall_snapshot() -> FirewallSnapshot:
    """Collect firewall ruleset summaries without changing system state."""
    commands = (
        (
            "nft",
            ("-j", "list", "ruleset"),
            "nftables",
            "nft -j list ruleset",
        ),
        (
            "iptables-save",
            (),
            "iptables",
            "iptables-save",
        ),
        (
            "ip6tables-save",
            (),
            "ip6tables",
            "ip6tables-save",
        ),
    )

    observations = []
    review = []
    detected = 0

    for executable, arguments, implementation, label in commands:
        executable_path = shutil.which(executable, path=_FIREWALL_PATH)
        if executable_path is None:
            continue

        detected += 1

        try:
            result = subprocess.run(
                [executable_path, *arguments],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=8,
                shell=False,
                env={
                    "PATH": _FIREWALL_PATH,
                    "LANG": "C",
                    "LC_ALL": "C",
                    "SYSTEMD_COLORS": "0",
                },
            )
        except (OSError, subprocess.SubprocessError) as error:
            message = (
                f"{label} could not complete ({type(error).__name__}); "
                "configuration was not assessed"
            )
            observation = FirewallObservation(
                implementation=implementation,
                state="NOT_ASSESSED",
                source=label,
                summary=message,
                review=(message,),
            )
        else:
            if result.returncode != 0:
                message = (
                    f"{label} exited with status {result.returncode}; "
                    "permissions or backend availability may limit collection"
                )
                observation = FirewallObservation(
                    implementation=implementation,
                    state="NOT_ASSESSED",
                    source=label,
                    summary=message,
                    review=(message,),
                )
            elif implementation == "nftables":
                observation = _parse_nft_json(result.stdout)
            else:
                observation = _parse_iptables_save(
                    result.stdout,
                    implementation=implementation,
                )

        observations.append(observation)
        review.extend(observation.review)

    if detected == 0:
        review.append(
            "No supported firewall inspection command was found; "
            "firewall state was not assessed"
        )

    return FirewallSnapshot(
        observations=tuple(observations),
        review=tuple(dict.fromkeys(review)),
    )
