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
    """Return a direct verdict before ambiguous control flow.

    JUMP, GOTO, and RETURN can change which subsequent rules are reached.
    Defer these cases to conservative assessment.
    """
    for rule in sorted(chain.rules, key=lambda item: item.position):
        if rule.target in {"JUMP", "GOTO", "RETURN"}:
            return None

        if rule.unconditional and rule.target in {"ACCEPT", "DROP", "REJECT"}:
            return rule

    return None



@dataclass(frozen=True, slots=True)
class _ChainFlowSummary:
    """Possible outcomes from a bounded, conservative chain traversal."""

    outcomes: tuple[str, ...]
    limitations: tuple[str, ...]

    @property
    def complete(self) -> bool:
        """Whether every explored path completed within the supported model."""
        return "UNRESOLVED" not in self.outcomes and not self.limitations


def _analyze_chain_flow(
    chain: FirewallChain,
    chain_index,
    *,
    max_states: int = 512,
    max_steps: int = 128,
    max_stack: int = 32,
) -> _ChainFlowSummary:
    """Explore possible outcomes without claiming full firewall semantics.

    Conditional rules are modeled as potentially matching and not matching.
    JUMP pushes a continuation, GOTO preserves the existing continuation,
    and RETURN resumes the caller or applies the base-chain policy.

    Unsupported actions, missing chains, loops, and exhausted budgets produce
    UNRESOLVED rather than being interpreted as secure or insecure.
    """
    root_key = (
        chain.implementation,
        chain.family,
        chain.table,
        chain.name,
    )
    root_policy = (chain.policy or "").upper()

    outcomes = set()
    limitations = set()

    # Each state contains:
    # chain key, rule index, return stack, states on the current path, steps.
    pending = [(root_key, 0, (), frozenset(), 0)]
    processed = 0

    continuing_targets = {
        "CONTINUE", "LOG", "ULOG", "NOTRACK", "TRACE",
    }

    def finish_at_base_policy():
        if root_policy in {"ACCEPT", "DROP", "REJECT"}:
            outcomes.add(f"POLICY_{root_policy}")
        else:
            outcomes.add("UNRESOLVED")
            limitations.add("base-chain policy unavailable or unsupported")

    while pending:
        if processed >= max_states:
            outcomes.add("UNRESOLVED")
            limitations.add(
                f"control-flow state budget exhausted ({max_states})"
            )
            break

        current_key, rule_index, stack, path, steps = pending.pop()
        processed += 1

        state = (current_key, rule_index, stack)

        if state in path:
            outcomes.add("UNRESOLVED")
            limitations.add(
                f"control-flow loop detected at chain {current_key[3]}"
            )
            continue

        if steps >= max_steps:
            outcomes.add("UNRESOLVED")
            limitations.add(
                f"control-flow step budget exhausted ({max_steps})"
            )
            continue

        current_chain = chain_index.get(current_key)
        if current_chain is None:
            outcomes.add("UNRESOLVED")
            limitations.add(
                f"chain metadata unavailable for {current_key[3]}"
            )
            continue

        ordered_rules = tuple(
            sorted(current_chain.rules, key=lambda item: item.position)
        )
        current_path = path | {state}

        # Falling off a user chain returns to its caller. If no caller frame
        # remains (including after GOTO from the base chain), use the base
        # chain policy.
        if rule_index >= len(ordered_rules):
            if stack:
                return_key, return_index = stack[-1]
                pending.append(
                    (
                        return_key,
                        return_index,
                        stack[:-1],
                        current_path,
                        steps + 1,
                    )
                )
            else:
                finish_at_base_policy()
            continue

        rule = ordered_rules[rule_index]
        action = (rule.target or "").upper()
        next_state = (
            current_key,
            rule_index + 1,
            stack,
            current_path,
            steps + 1,
        )

        # A conditional rule has both a match path and a non-match path.
        # For terminal/control-flow actions, the non-match path proceeds
        # to the next rule. Ordinary continuing actions need only one path.
        if action in {"ACCEPT", "DROP", "REJECT"}:
            if not rule.unconditional:
                pending.append(next_state)
            outcomes.add(action)
            continue

        if action == "RETURN":
            if not rule.unconditional:
                pending.append(next_state)

            if stack:
                return_key, return_index = stack[-1]
                pending.append(
                    (
                        return_key,
                        return_index,
                        stack[:-1],
                        current_path,
                        steps + 1,
                    )
                )
            else:
                finish_at_base_policy()
            continue

        if action in {"JUMP", "GOTO"}:
            if not rule.unconditional:
                pending.append(next_state)

            if not rule.target_chain:
                outcomes.add("UNRESOLVED")
                limitations.add(
                    f"{action} target missing at "
                    f"{current_key[3]} rule {rule.position}"
                )
                continue

            target_key = (
                current_key[0],
                current_key[1],
                current_key[2],
                rule.target_chain,
            )

            if target_key not in chain_index:
                outcomes.add("UNRESOLVED")
                limitations.add(
                    f"referenced chain unavailable: {rule.target_chain}"
                )
                continue

            if action == "JUMP":
                if len(stack) >= max_stack:
                    outcomes.add("UNRESOLVED")
                    limitations.add(
                        f"maximum nested-chain call depth reached ({max_stack})"
                    )
                    continue

                next_stack = stack + ((current_key, rule_index + 1),)
            else:
                # GOTO enters the target without adding a continuation for
                # the remainder of the current chain.
                next_stack = stack

            pending.append(
                (target_key, 0, next_stack, current_path, steps + 1)
            )
            continue

        if not action or action in continuing_targets:
            pending.append(next_state)
            continue

        # Unknown targets may terminate processing or behave like a
        # continuing target. Preserve both the uncertainty and a possible
        # continuation instead of guessing their semantics.
        outcomes.add("UNRESOLVED")
        limitations.add(
            f"unsupported target {action} at "
            f"{current_key[3]} rule {rule.position}"
        )
        pending.append(next_state)

    return _ChainFlowSummary(
        outcomes=tuple(sorted(outcomes)),
        limitations=tuple(sorted(limitations)),
    )


def _chain_flow_note(summary: _ChainFlowSummary) -> str:
    """Format path-analysis evidence with explicit uncertainty."""
    outcomes = ", ".join(summary.outcomes) if summary.outcomes else "none"
    note = (
        f" Bounded control-flow outcomes: {outcomes}. "
        "Conditional rules are explored as match/no-match branches; "
        "correlations between conditions and interactions with other "
        "hooks or firewall backends are not resolved."
    )

    if summary.limitations:
        note += (
            " Analysis incomplete: "
            + "; ".join(summary.limitations)
            + "."
        )

    return note


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
    """Summarize nested custom-chain actions without judging coverage.

    Nested JUMP/GOTO references are followed for explanatory reporting only.
    Cycles, missing metadata, and excessive traversal are reported explicitly.
    This is not a full firewall control-flow evaluator.
    """
    targets = tuple(
        dict.fromkeys(
            rule.target_chain
            for rule in sorted(chain.rules, key=lambda item: item.position)
            if rule.target in {"JUMP", "GOTO"} and rule.target_chain
        )
    )
    if not targets:
        return ""

    max_depth = 8
    remaining_references = [64]
    root_key = (
        chain.implementation,
        chain.family,
        chain.table,
        chain.name,
    )

    def summarize(
        name: str,
        ancestry: tuple[tuple[str, str, str, str], ...],
        depth: int,
    ) -> str:
        key = (
            chain.implementation,
            chain.family,
            chain.table,
            name,
        )

        if key in ancestry:
            return f"{name}: circular chain reference detected"

        target = chain_index.get(key)
        if target is None:
            return f"{name}: chain metadata unavailable"

        if not target.rules:
            return f"{name}: no rule actions collected"

        if depth > max_depth:
            return f"{name}: maximum nested-chain analysis depth reached"

        if remaining_references[0] <= 0:
            return f"{name}: nested-chain reference limit reached"

        remaining_references[0] -= 1
        path = ancestry + (key,)
        action_parts = []

        for rule in sorted(target.rules, key=lambda item: item.position):
            action = (
                f"rule {rule.position}={rule.target or 'unknown'} "
                f"({'unconditional' if rule.unconditional else 'conditional'})"
            )

            if rule.conditions:
                action += "; matches: " + " AND ".join(rule.conditions)

            if rule.target in {"JUMP", "GOTO"} and rule.target_chain:
                nested = summarize(rule.target_chain, path, depth + 1)
                action += f"; {rule.target.lower()} -> {nested}"

            action_parts.append(action)

        return f"{name}: " + ", ".join(action_parts)

    summaries = [
        summarize(name, (root_key,), 1)
        for name in targets
    ]

    return (
        " Referenced custom-chain rule actions: "
        + "; ".join(summaries)
        + ". The analyzer does not prove that these conditions cover all traffic."
    )



def _reachable_accept_finding(
    chain: FirewallChain,
    hook: str,
    flow: _ChainFlowSummary,
    verdict,
) -> Finding | None:
    """Create a REVIEW finding for a reachable ACCEPT path when needed."""
    if "ACCEPT" not in flow.outcomes:
        return None

    if verdict is not None and verdict.target == "ACCEPT":
        # The existing direct-verdict rule already reports this case.
        return None

    policy = (chain.policy or "").upper()

    # A base-policy finding already covers accepting behavior and uncertainty
    # when the base policy may be reached or the traversal is incomplete.
    if policy == "ACCEPT" and (
        "POLICY_ACCEPT" in flow.outcomes or not flow.complete
    ):
        return None

    label = _chain_label(chain)
    hook_title = "Input" if hook == "input" else "Forwarding"
    evidence = (
        f"{label}: a potentially reachable ACCEPT verdict was identified."
        f"{_chain_flow_note(flow)}"
    )

    return _review_finding(
        rule_id=_family_rule_id(
            f"FIREWALL-{hook.upper()}-ACCEPT-001",
            chain,
        ),
        title=f"{hook_title} chain has a potentially reachable ACCEPT path",
        evidence=evidence,
        explanation=(
            "The collected rules provide a possible ACCEPT path within the "
            "supported control-flow model. Conditional matches, additional "
            "hooks, and other firewall backends can change actual outcomes. "
            "This does not prove remote reachability."
        ),
        recommendation=(
            "Review the rules and conditions on this path together with "
            "other active hooks. Resolve any reported analysis limitations "
            "before relying on this result."
        ),
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
        flow = _analyze_chain_flow(chain, chain_index)
        flow_note = _chain_flow_note(flow)

        accept_finding = _reachable_accept_finding(
            chain, "input", flow, verdict
        )
        if accept_finding is not None:
            checks.append(f"REVIEW · {accept_finding.evidence}")
            findings.append(accept_finding)

        if verdict is not None and verdict.target == "ACCEPT":
            evidence = (
                f"{label}: unconditional ACCEPT at rule {verdict.position}; "
                f"chain policy={policy or 'unknown'}.{flow_note}"
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
                "firewall hooks can change individual outcomes." + flow_note
            )
            continue

        if policy in {"DROP", "REJECT"}:
            checks.append(
                f"POLICY OBSERVED · {label}: default policy {policy} "
                "denies packets not otherwise given a terminal verdict."
                + flow_note
            )
            continue

        if policy == "ACCEPT":
            if flow.complete and "POLICY_ACCEPT" not in flow.outcomes:
                evidence = (
                    f"{label}: default policy ACCEPT was not reachable "
                    f"in the bounded control-flow analysis.{flow_note}"
                )
                checks.append(f"POLICY OBSERVED · {evidence}")
                continue

            evidence = (
                f"{label}: default policy ACCEPT and no unconditional "
                "DROP/REJECT fallback was identified." + flow_note
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

        evidence = f"{label}: no recognizable default policy was available.{flow_note}"
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
        flow = _analyze_chain_flow(chain, chain_index)
        flow_note = _chain_flow_note(flow)
        jump_note = _jump_chain_note(chain, chain_index) + flow_note

        accept_finding = _reachable_accept_finding(
            chain, "forward", flow, verdict
        )
        if accept_finding is not None:
            checks.append(f"REVIEW · {accept_finding.evidence}")
            findings.append(accept_finding)

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
            if flow.complete and "POLICY_ACCEPT" not in flow.outcomes:
                evidence = (
                    f"{label}: default policy ACCEPT was not reachable "
                    f"in the bounded control-flow analysis.{jump_note}"
                )
                checks.append(f"POLICY OBSERVED · {evidence}")
                continue

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

        evidence = f"{label}: no recognizable forwarding policy was available.{jump_note}"
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
