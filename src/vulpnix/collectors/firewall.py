"""Read-only firewall discovery and configuration inventory."""

import json
import ipaddress
import re
import shlex
import shutil
import subprocess

from vulpnix.models.firewall import (
    FirewallChain,
    FirewallObservation,
    FirewallRule,
    FirewallSnapshot,
)



def _nft_operand_text(value) -> str | None:
    """Describe common nftables operands without inventing interpretations."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return repr(value)

    if isinstance(value, list):
        items = [_nft_operand_text(item) for item in value]
        if all(item is not None for item in items):
            return "{" + ", ".join(items) + "}"
        return None

    if not isinstance(value, dict) or len(value) != 1:
        return None

    kind, item = next(iter(value.items()))

    if kind == "prefix" and isinstance(item, dict):
        address = item.get("addr")
        prefix_length = item.get("len")
        if (
            isinstance(address, str)
            and isinstance(prefix_length, int)
            and not isinstance(prefix_length, bool)
        ):
            try:
                return str(
                    ipaddress.ip_network(
                        f"{address}/{prefix_length}", strict=False
                    )
                )
            except ValueError:
                return None


    if kind in {"meta", "ct"} and isinstance(item, dict):
        key = item.get("key")
        if isinstance(key, str):
            return f"{kind} {key}"
        return None

    if kind == "payload" and isinstance(item, dict):
        protocol = item.get("protocol")
        field = item.get("field")
        if isinstance(field, str):
            prefix = f"{protocol} " if isinstance(protocol, str) else ""
            return f"payload {prefix}{field}"
        return None

    if kind == "set" and isinstance(item, list):
        rendered = [_nft_operand_text(entry) for entry in item]
        if all(entry is not None for entry in rendered):
            return "{" + ", ".join(rendered) + "}"
        return None

    if kind == "range" and isinstance(item, list) and len(item) == 2:
        left, right = (_nft_operand_text(entry) for entry in item)
        if left is not None and right is not None:
            return f"{left} .. {right}"
        return None

    if kind == "concat" and isinstance(item, list):
        parts = [_nft_operand_text(entry) for entry in item]
        if all(part is not None for part in parts):
            return "concat(" + ", ".join(parts) + ")"
        return None

    return None


def _nft_match_conditions(expressions) -> tuple[str, ...]:
    """Extract readable equality/range match predicates from nft JSON."""
    if not isinstance(expressions, list):
        return ()

    conditions = []
    for expression in expressions:
        if not isinstance(expression, dict):
            continue
        match = expression.get("match")
        if not isinstance(match, dict):
            continue

        left = _nft_operand_text(match.get("left"))
        operator = match.get("op")
        right = _nft_operand_text(match.get("right"))
        if not isinstance(operator, str):
            conditions.append("nft match condition could not be rendered (operator unavailable)")
        elif left is None or right is None:
            conditions.append(
                f"nft match condition could not be rendered (operator {operator!r})"
            )
        else:
            conditions.append(f"{left} {operator} {right}")

    return tuple(conditions)


def _iptables_condition_text(tokens: list[str]) -> tuple[str, ...]:
    """Preserve match tokens while excluding counters and comment-only metadata."""
    cleaned = []
    index = 0
    while index < len(tokens):
        if tokens[index] == "-c" and index + 2 < len(tokens):
            index += 3
            continue
        if (
            tokens[index] == "-m"
            and index + 1 < len(tokens)
            and tokens[index + 1] == "comment"
        ):
            index += 2
            if index < len(tokens) and tokens[index] == "--comment":
                index += 2
            continue
        if tokens[index] == "--comment" and index + 1 < len(tokens):
            index += 2
            continue
        cleaned.append(tokens[index])
        index += 1

    return (" ".join(cleaned),) if cleaned else ()


def _nft_rule_metadata(expressions, position: int) -> FirewallRule:
    """Extract terminal action and whether preceding expressions restrict it."""
    if not isinstance(expressions, list):
        return FirewallRule(position, None, False)

    verdicts = ("accept", "drop", "reject", "return", "jump", "goto")
    harmless = {"counter", "comment", "log"}

    for index, expression in enumerate(expressions):
        if not isinstance(expression, dict):
            continue
        action = next((key for key in verdicts if key in expression), None)
        if action is None:
            continue

        value = expression[action]
        target = (
            value.get("target")
            if action in {"jump", "goto"} and isinstance(value, dict)
            else None
        )
        unconditional = all(
            isinstance(previous, dict)
            and len(previous) == 1
            and next(iter(previous)) in harmless
            for previous in expressions[:index]
        )
        return FirewallRule(
            position=position,
            target=action.upper(),
            unconditional=unconditional,
            target_chain=target if isinstance(target, str) else None,
            conditions=_nft_match_conditions(expressions[:index]),
        )

    return FirewallRule(position, None, False)


def _parse_nft_chains(output: str) -> tuple[FirewallChain, ...]:
    """Preserve nftables base-chain metadata and ordered terminal actions."""
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return ()

    if not isinstance(payload, dict) or not isinstance(payload.get("nftables"), list):
        return ()

    chain_data = {}
    rules_by_chain = {}

    for entry in payload["nftables"]:
        if not isinstance(entry, dict):
            continue

        chain = entry.get("chain")
        if isinstance(chain, dict):
            family, table, name = (
                chain.get("family"),
                chain.get("table"),
                chain.get("name"),
            )
            if all(isinstance(value, str) and value for value in (family, table, name)):
                key = (family, table, name)
                chain_data[key] = {
                    "hook": chain.get("hook") if isinstance(chain.get("hook"), str) else None,
                    "policy": chain.get("policy").upper()
                    if isinstance(chain.get("policy"), str)
                    else None,
                    "chain_type": chain.get("type")
                    if isinstance(chain.get("type"), str)
                    else None,
                }
                rules_by_chain.setdefault(key, [])

        rule = entry.get("rule")
        if isinstance(rule, dict):
            family, table, name = (
                rule.get("family"),
                rule.get("table"),
                rule.get("chain"),
            )
            if all(isinstance(value, str) and value for value in (family, table, name)):
                key = (family, table, name)
                ordered = rules_by_chain.setdefault(key, [])
                ordered.append(
                    _nft_rule_metadata(rule.get("expr"), len(ordered) + 1)
                )

    return tuple(
        FirewallChain(
            implementation="nftables",
            family=family,
            table=table,
            name=name,
            hook=data["hook"],
            policy=data["policy"],
            rules=tuple(rules_by_chain.get((family, table, name), ())),
            chain_type=data["chain_type"],
        )
        for (family, table, name), data in chain_data.items()
    )


def _iptables_has_match(tokens: list[str]) -> bool:
    """Conservatively detect match conditions before an iptables verdict."""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-c" and index + 2 < len(tokens):
            index += 3
            continue
        if (
            token == "-m"
            and index + 1 < len(tokens)
            and tokens[index + 1] == "comment"
        ):
            index += 2
            if index < len(tokens) and tokens[index] == "--comment":
                index += 2
            continue
        if token == "--comment" and index + 1 < len(tokens):
            index += 2
            continue
        return True
    return False


def _parse_iptables_chains(
    output: str, *, implementation: str
) -> tuple[FirewallChain, ...]:
    """Preserve iptables policies and ordered rule actions."""
    family = {"iptables": "ipv4", "ip6tables": "ipv6"}.get(
        implementation, "unknown"
    )
    chain_data = {}
    raw_rules = {}
    current_table = None

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            current_table = line[1:].strip() or None
            continue
        if line == "COMMIT":
            current_table = None
            continue

        if line.startswith(":") and current_table is not None:
            match = re.fullmatch(r":(\S+)\s+(\S+)\s+\[\d+:\d+\]", line)
            if match is None:
                continue
            name, policy_text = match.groups()
            hook = (
                name.lower()
                if current_table == "filter"
                and name in {"INPUT", "FORWARD", "OUTPUT"}
                else None
            )
            key = (current_table, name)
            chain_data[key] = {
                "policy": None if policy_text == "-" else policy_text.upper(),
                "hook": hook,
            }
            raw_rules.setdefault(key, [])
            continue

        if line.startswith("-A ") and current_table is not None:
            try:
                tokens = shlex.split(line)
            except ValueError:
                continue
            if len(tokens) >= 3 and tokens[0] == "-A":
                raw_rules.setdefault((current_table, tokens[1]), []).append(tokens[2:])

    names_by_table = {}
    for table_name, chain_name in chain_data:
        names_by_table.setdefault(table_name, set()).add(chain_name)

    verdicts = {
        "ACCEPT", "DROP", "REJECT", "RETURN", "QUEUE", "NFQUEUE",
        "LOG", "ULOG", "CONTINUE", "NOTRACK",
    }
    result = []

    for (table_name, chain_name), data in chain_data.items():
        rules = []
        for position, tokens in enumerate(raw_rules.get((table_name, chain_name), ()), 1):
            jump_index = next(
                (
                    index for index, token in enumerate(tokens)
                    if token in {"-j", "--jump", "-g", "--goto"}
                    and index + 1 < len(tokens)
                ),
                None,
            )
            if jump_index is None:
                rules.append(FirewallRule(position, None, False))
                continue

            target = tokens[jump_index + 1]
            target_chain = (
                target
                if target in names_by_table.get(table_name, set())
                and target.upper() not in verdicts
                else None
            )
            rules.append(
                FirewallRule(
                    position=position,
                    target=target.upper() if target.upper() in verdicts else target,
                    unconditional=not _iptables_has_match(tokens[:jump_index]),
                    target_chain=target_chain,
                    conditions=_iptables_condition_text(tokens[:jump_index]),
                )
            )

        result.append(
            FirewallChain(
                implementation=implementation,
                family=family,
                table=table_name,
                name=chain_name,
                hook=data["hook"],
                policy=data["policy"],
                rules=tuple(rules),
                chain_type=table_name,
            )
        )

    return tuple(result)


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
        chains=_parse_nft_chains(output),
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
        chains=_parse_iptables_chains(output, implementation=implementation),
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
