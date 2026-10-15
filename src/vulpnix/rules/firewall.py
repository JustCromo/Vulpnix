"""Conservative assessment of collected firewall input-chain policies."""

from dataclasses import dataclass

from vulpnix.findings import Finding, FindingStatus
from vulpnix.models import FirewallChain, FirewallSnapshot


@dataclass(frozen=True, slots=True)
class FirewallPolicyAssessment:
    """Policy observations, review findings, and remaining review count."""

    checks: tuple[str, ...]
    findings: tuple[Finding, ...]
    review_items: int


def _is_supported_base_chain(chain: FirewallChain, hook: str) -> bool:
    if (chain.hook or "").lower() != hook:
        return False
    if chain.implementation == "nftables":
        return (chain.chain_type or "").lower() == "filter"
    if chain.implementation in {"iptables", "ip6tables"}:
        return chain.table == "filter"
    return False


def _is_supported_input_chain(chain: FirewallChain) -> bool:
    return _is_supported_base_chain(chain, "input")


def _is_supported_forward_chain(chain: FirewallChain) -> bool:
    return _is_supported_base_chain(chain, "forward")


def _first_unconditional_verdict(chain: FirewallChain):
    for rule in sorted(chain.rules, key=lambda item: item.position):
        if rule.unconditional and rule.target in {"ACCEPT", "DROP", "REJECT"}:
            return rule
    return None


def _chain_label(chain: FirewallChain) -> str:
    return (
        f"{chain.implementation} {chain.family}/"
        f"{chain.table}/{chain.name}"
    )


def _family_rule_id(rule_id: str, chain) -> str:
    """Distinguish IPv4/IPv6 findings while preserving other family IDs."""
    family = str(chain.family).lower()
    token = {
        "ip": "IPV4",
        "ipv4": "IPV4",
        "ip6": "IPV6",
        "ipv6": "IPV6",
    }.get(family)

    # In particular, keep existing IDs for inet-based rulesets.
    if token is None:
        return rule_id

    prefix, separator, number = rule_id.rpartition("-")
    if separator and number.isdigit():
        return f"{prefix}-{token}-{number}"
    return f"{rule_id}-{token}"


def _review_finding(
    *,
    rule_id: str,
    title: str,
    evidence: str,
    explanation: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        evidence=evidence,
        explanation=explanation,
        recommendation=recommendation,
        status=FindingStatus.REVIEW,
    )


def _jump_chain_note(chain: FirewallChain, chain_index) -> str:
    """Summarize rule actions in referenced custom chains without judging coverage."""
    targets = tuple(
        dict.fromkeys(
            rule.target_chain
            for rule in sorted(chain.rules, key=lambda item: item.position)
            if rule.target in {"JUMP", "GOTO"} and rule.target_chain
        )
    )
    if not targets:
        return ""

    summaries = []
    for name in targets:
        target = chain_index.get(
            (chain.implementation, chain.family, chain.table, name)
        )
        if target is None:
            summaries.append(f"{name}: chain metadata unavailable")
            continue
        if not target.rules:
            summaries.append(f"{name}: no rule actions collected")
            continue

        action_parts = []
        for rule in sorted(target.rules, key=lambda item: item.position):
            action = (
                f"rule {rule.position}={rule.target or 'unknown'} "
                f"({'unconditional' if rule.unconditional else 'conditional'})"
            )
            if rule.conditions:
                action += "; matches: " + " AND ".join(rule.conditions)
            action_parts.append(action)
        actions = ", ".join(action_parts)
        summaries.append(f"{name}: {actions}")

    return (
        " Referenced custom-chain rule actions: "
        + "; ".join(summaries)
        + ". The analyzer does not prove that these conditions cover all traffic."
    )


def assess_firewall_policy(
    snapshot: FirewallSnapshot,
) -> FirewallPolicyAssessment:
    """Assess input and forwarding base chains conservatively.

    This does not prove remote reachability, fully resolve custom-chain paths,
    or reconcile every active firewall backend. Ambiguous policies produce
    REVIEW findings rather than confirmed vulnerabilities.
    """
    checks: list[str] = []
    findings: list[Finding] = []
    configured = tuple(
        observation
        for observation in snapshot.observations
        if observation.state == "CONFIGURED"
    )
    all_chains = tuple(
        chain for observation in configured for chain in observation.chains
    )
    chain_index = {
        (chain.implementation, chain.family, chain.table, chain.name): chain
        for chain in all_chains
    }

    input_chains = tuple(
        chain
        for observation in configured
        for chain in observation.chains
        if _is_supported_input_chain(chain)
    )
    forward_chains = tuple(
        chain
        for observation in configured
        for chain in observation.chains
        if _is_supported_forward_chain(chain)
    )

    # Host-directed traffic and forwarded traffic are separate assessments.
    if not input_chains:
        collection_available = any(
            observation.state in {"CONFIGURED", "EMPTY"}
            for observation in snapshot.observations
        )
        if collection_available or not snapshot.observations:
            observed_base_chains = tuple(
                chain
                for observation in configured
                for chain in observation.chains
                if chain.hook
            )
            if observed_base_chains:
                observed = "; ".join(
                    f"{_chain_label(chain)} hook={chain.hook} "
                    f"policy={chain.policy or 'unknown'}"
                    for chain in observed_base_chains[:6]
                )
                omitted = len(observed_base_chains) - 6
                suffix = (
                    f"; {omitted} additional base chain(s) omitted"
                    if omitted > 0
                    else ""
                )
                evidence = (
                    "No supported base input filter chain was available "
                    f"in the collected rulesets. Other observed base chains: "
                    f"{observed}{suffix}."
                )
            else:
                evidence = (
                    "No supported base input filter chain was available "
                    "in the collected rulesets, and no other base-chain "
                    "hooks were identified."
                )
            checks.append(f"REVIEW · {evidence}")
            findings.append(
                _review_finding(
                    rule_id="FIREWALL-INPUT-UNASSESSED-001",
                    title="Inbound firewall policy could not be assessed",
                    evidence=evidence,
                    explanation=(
                        "The collected data did not contain a supported "
                        "INPUT/input filter chain. This does not prove that "
                        "the host has no firewall; another backend, a "
                        "different chain layout, or unavailable rule data "
                        "may be involved."
                    ),
                    recommendation=(
                        "Verify which firewall backend and input hooks are "
                        "active, and confirm whether the collected rulesets "
                        "expose the applicable input filter chain. If rule "
                        "collection is incomplete or lacks permissions, "
                        "resolve that limitation; otherwise, review support "
                        "for the detected chain layout before drawing a "
                        "conclusion."
                    ),
                )
            )

    for chain in input_chains:
        label = _chain_label(chain)
        policy = (chain.policy or "").upper()
        verdict = _first_unconditional_verdict(chain)

        if verdict is not None and verdict.target == "ACCEPT":
            evidence = (
                f"{label}: unconditional ACCEPT at rule {verdict.position}; "
                f"chain policy={policy or 'unknown'}."
            )
            checks.append(
                f"REVIEW · {evidence} Packets reaching this rule are "
                "accepted by this chain."
            )
            findings.append(
                _review_finding(
                    rule_id=_family_rule_id("FIREWALL-INPUT-ACCEPT-001", chain),
                    title="Input chain has an unconditional ACCEPT rule",
                    evidence=evidence,
                    explanation=(
                        "An unconditional ACCEPT terminates evaluation for "
                        "packets that reach that rule. Earlier conditional "
                        "rules and other hooks or backends may affect the "
                        "outcome, so this does not prove remote exposure."
                    ),
                    recommendation=(
                        "Review this rule, preceding conditions, exposed "
                        "services, and the host's other active firewall hooks."
                    ),
                )
            )
            continue

        if verdict is not None and verdict.target in {"DROP", "REJECT"}:
            checks.append(
                f"POLICY OBSERVED · {label}: unconditional "
                f"{verdict.target} at rule {verdict.position} blocks "
                "packets that reach that rule; preceding rules and other "
                "firewall hooks can change individual outcomes."
            )
            continue

        if policy in {"DROP", "REJECT"}:
            checks.append(
                f"POLICY OBSERVED · {label}: default policy {policy} "
                "denies packets not otherwise given a terminal verdict."
            )
            continue

        if policy == "ACCEPT":
            evidence = (
                f"{label}: default policy ACCEPT and no unconditional "
                "DROP/REJECT fallback was identified."
            )
            checks.append(f"REVIEW · {evidence}")
            findings.append(
                _review_finding(
                    rule_id=_family_rule_id("FIREWALL-INPUT-POLICY-001", chain),
                    title="Input chain has a permissive default policy",
                    evidence=evidence,
                    explanation=(
                        "Unmatched packets reaching the end of this chain "
                        "are accepted. Specific rules and other firewall "
                        "hooks may still restrict traffic."
                    ),
                    recommendation=(
                        "Review whether unsolicited inbound connections "
                        "are required and whether explicit allow rules with "
                        "a restrictive fallback are appropriate."
                    ),
                )
            )
            continue

        evidence = f"{label}: no recognizable default policy was available."
        checks.append(f"REVIEW · {evidence}")
        findings.append(
            _review_finding(
                rule_id=_family_rule_id("FIREWALL-INPUT-POLICY-002", chain),
                title="Input chain policy is not recognized",
                evidence=evidence,
                explanation=(
                    "The analyzer cannot determine how unmatched traffic "
                    "is handled by this chain."
                ),
                recommendation="Inspect the chain policy and collected ruleset.",
            )
        )

    for chain in forward_chains:
        label = _chain_label(chain)
        policy = (chain.policy or "").upper()
        verdict = _first_unconditional_verdict(chain)
        jump_note = _jump_chain_note(chain, chain_index)

        if verdict is not None and verdict.target == "ACCEPT":
            evidence = (
                f"{label}: unconditional ACCEPT at rule {verdict.position}; "
                f"chain policy={policy or 'unknown'}.{jump_note}"
            )
            checks.append(f"REVIEW · {evidence}")
            findings.append(
                _review_finding(
                    rule_id=_family_rule_id("FIREWALL-FORWARD-ACCEPT-001", chain),
                    title="Forwarding chain has an unconditional ACCEPT rule",
                    evidence=evidence,
                    explanation=(
                        "Forwarded packets reaching this rule are accepted "
                        "by this chain. The analyzer does not establish that "
                        "forwarding is enabled, that a route exists, or that "
                        "other hooks and backends permit the traffic."
                    ),
                    recommendation=(
                        "Review the intended forwarding role, preceding "
                        "rules, downstream chains, and relevant interfaces."
                    ),
                )
            )
            continue

        if verdict is not None and verdict.target in {"DROP", "REJECT"}:
            checks.append(
                f"POLICY OBSERVED · {label}: unconditional "
                f"{verdict.target} at rule {verdict.position}.{jump_note}"
            )
            continue

        if policy in {"DROP", "REJECT"}:
            checks.append(
                f"POLICY OBSERVED · {label}: default policy {policy} "
                f"denies forwarded packets without another terminal verdict."
                f"{jump_note}"
            )
            continue

        if policy == "ACCEPT":
            evidence = (
                f"{label}: default policy ACCEPT and no unconditional "
                f"DROP/REJECT fallback was identified.{jump_note}"
            )
            checks.append(f"REVIEW · {evidence}")
            findings.append(
                _review_finding(
                    rule_id=_family_rule_id("FIREWALL-FORWARD-POLICY-001", chain),
                    title="Forwarding chain has a permissive default policy",
                    evidence=evidence,
                    explanation=(
                        "Forwarded packets that leave this chain without "
                        "a terminal verdict are accepted by its default "
                        "policy. This alone does not establish whether IP "
                        "forwarding is enabled, a route exists, or traffic "
                        "is reachable. Custom chains require fuller analysis."
                    ),
                    recommendation=(
                        "Confirm whether the host is intended to route or "
                        "bridge traffic. Review custom-chain rules and use "
                        "a restrictive fallback where appropriate."
                    ),
                )
            )
            continue

        evidence = f"{label}: no recognizable forwarding policy was available."
        checks.append(f"REVIEW · {evidence}")
        findings.append(
            _review_finding(
                rule_id=_family_rule_id("FIREWALL-FORWARD-POLICY-002", chain),
                title="Forwarding chain policy is not recognized",
                evidence=evidence,
                explanation=(
                    "The analyzer cannot determine how unmatched forwarded "
                    "packets are handled by this chain."
                ),
                recommendation=(
                    "Inspect the forwarding chain and its relevant firewall rules."
                ),
            )
        )

    return FirewallPolicyAssessment(
        checks=tuple(checks),
        findings=tuple(findings),
        review_items=len(findings),
    )
