"""Evidence-based assessment of selected Linux kernel hardening parameters."""

from dataclasses import dataclass

from vulpnix.findings import Finding, FindingStatus
from vulpnix.models import HardeningAssessment, HardeningCheck, SysctlObservation


@dataclass(frozen=True, slots=True)
class _Rule:
    key: str
    title: str
    expected: str
    pass_values: frozenset[int]
    fail_values: frozenset[int]
    explanation: str
    recommendation: str
    optional: bool = False
    context_sensitive: bool = False


_RULES = (
    _Rule("kernel.dmesg_restrict", "Restrict kernel log access", "1", frozenset({1}), frozenset({0}), "Restricting unprivileged access to kernel logs can reduce disclosure of system details.", "Keep kernel.dmesg_restrict enabled unless a documented operational requirement justifies otherwise."),
    _Rule("kernel.kptr_restrict", "Restrict kernel pointer exposure", "1 or 2", frozenset({1, 2}), frozenset({0}), "Exposed kernel pointers can make kernel attack-surface analysis easier.", "Set kernel.kptr_restrict to 1 or 2 according to the host's observability requirements."),
    _Rule("kernel.yama.ptrace_scope", "Restrict process tracing", "1, 2, or 3", frozenset({1, 2, 3}), frozenset(), "A ptrace scope of zero allows broader same-user process tracing.", "Consider a ptrace_scope of 1 or higher when debugging requirements permit.", optional=True, context_sensitive=True),
    _Rule("fs.protected_hardlinks", "Protect hard links", "1", frozenset({1}), frozenset({0}), "Protected hard links reduce opportunities to create links to files the caller cannot safely modify.", "Enable fs.protected_hardlinks."),
    _Rule("fs.protected_symlinks", "Protect sticky-directory symlinks", "1", frozenset({1}), frozenset({0}), "Protected symlinks reduce attacks through symlinks in world-writable sticky directories.", "Enable fs.protected_symlinks."),
    _Rule("fs.suid_dumpable", "Limit privileged-process core dumps", "0", frozenset({0}), frozenset(), "Core-dump behavior for set-ID programs can expose sensitive process state.", "Review whether fs.suid_dumpable should remain zero on this host.", context_sensitive=True),
    _Rule("net.ipv4.conf.all.accept_redirects", "IPv4 ICMP redirects (all interfaces)", "0", frozenset({0}), frozenset(), "Accepting router redirects changes routing behavior and may be inappropriate on ordinary hosts.", "Disable acceptance unless the network role explicitly requires it.", context_sensitive=True),
    _Rule("net.ipv4.conf.default.accept_redirects", "IPv4 ICMP redirects (default interfaces)", "0", frozenset({0}), frozenset(), "New interfaces inherit this redirect policy.", "Disable acceptance unless the network role explicitly requires it.", context_sensitive=True),
    _Rule("net.ipv4.conf.all.accept_source_route", "IPv4 source routing (all interfaces)", "0", frozenset({0}), frozenset({1}), "Source-routed packets allow the sender more influence over packet routing.", "Disable IPv4 source routing unless a documented requirement exists."),
    _Rule("net.ipv4.conf.default.accept_source_route", "IPv4 source routing (default interfaces)", "0", frozenset({0}), frozenset({1}), "New interfaces inherit this source-routing policy.", "Disable IPv4 source routing unless a documented requirement exists."),
    _Rule("net.ipv4.conf.all.send_redirects", "IPv4 ICMP redirect sending", "0", frozenset({0}), frozenset(), "Sending redirects can be valid on routers but is usually unnecessary on end hosts.", "Confirm this host's routing role; disable redirects on ordinary endpoints.", context_sensitive=True),
    _Rule("net.ipv4.conf.all.rp_filter", "IPv4 reverse-path filtering", "1 or 2", frozenset({1, 2}), frozenset(), "Reverse-path filtering can reduce source-address spoofing, but strict routing environments may need a different mode.", "Review routing requirements; consider loose (2) or strict (1) reverse-path filtering.", context_sensitive=True),
    _Rule("net.ipv6.conf.all.accept_redirects", "IPv6 ICMP redirects (all interfaces)", "0", frozenset({0}), frozenset(), "Accepting IPv6 router redirects changes routing behavior.", "Disable acceptance unless the network role explicitly requires it.", optional=True, context_sensitive=True),
    _Rule("net.ipv6.conf.default.accept_redirects", "IPv6 ICMP redirects (default interfaces)", "0", frozenset({0}), frozenset(), "New IPv6 interfaces inherit this redirect policy.", "Disable acceptance unless the network role explicitly requires it.", optional=True, context_sensitive=True),
)


def assess_kernel_hardening(observations: tuple[SysctlObservation, ...]) -> HardeningAssessment:
    """Assess known values; context-sensitive deviations become REVIEW, never guessed FAIL."""
    observed_by_key = {item.key: item for item in observations}
    checks: list[HardeningCheck] = []
    findings: list[Finding] = []

    for rule in _RULES:
        observation = observed_by_key.get(rule.key)
        optional = rule.optional
        value = observation.value if observation else None
        error = observation.error if observation else "collector did not return this parameter"
        if value is None:
            status = FindingStatus.NOT_ASSESSED
            reason = error or "value unavailable"
            evidence = f"{rule.key}: NOT_ASSESSED ({reason})"
            check = HardeningCheck(rule.key, rule.title, rule.key, None, rule.expected, status, rule.explanation, rule.recommendation, reason, optional)
            checks.append(check)
            if not optional:
                findings.append(Finding(
                    rule_id=f"KERNEL-HARDENING-{rule.key.upper().replace('.', '-').replace('_', '-')}",
                    title=f"Could not assess: {rule.title}",
                    evidence=evidence,
                    explanation="The expected kernel setting could not be read reliably; this is not evidence that the setting is insecure.",
                    recommendation="Retry with appropriate privileges or verify whether this kernel exposes the parameter.",
                    status=FindingStatus.NOT_ASSESSED,
                ))
            continue

        try:
            numeric = int(value, 10)
        except ValueError:
            status = FindingStatus.ERROR
            reason = "value was not an integer"
            check = HardeningCheck(rule.key, rule.title, rule.key, value, rule.expected, status, rule.explanation, rule.recommendation, reason, optional)
            checks.append(check)
            findings.append(Finding(
                rule_id=f"KERNEL-HARDENING-{rule.key.upper().replace('.', '-').replace('_', '-')}",
                title=f"Could not assess: {rule.title}",
                evidence=f"{rule.key} contained a non-integer value",
                explanation="The collector received data outside the documented integer form; no security conclusion was made.",
                recommendation="Review the kernel interface and Vulpnix compatibility before drawing a conclusion.",
                status=FindingStatus.ERROR,
            ))
            continue

        if numeric in rule.pass_values:
            status = FindingStatus.PASS
            reason = None
        elif numeric in rule.fail_values:
            status = FindingStatus.FAIL
            reason = None
        elif rule.context_sensitive:
            status = FindingStatus.REVIEW
            reason = "the value may be appropriate for some host roles"
        else:
            status = FindingStatus.REVIEW
            reason = "value falls outside the explicitly assessed range"

        check = HardeningCheck(rule.key, rule.title, rule.key, value, rule.expected, status, rule.explanation, rule.recommendation, reason, optional)
        checks.append(check)
        if status is not FindingStatus.PASS:
            findings.append(Finding(
                rule_id=f"KERNEL-HARDENING-{rule.key.upper().replace('.', '-').replace('_', '-')}",
                title=rule.title if status is FindingStatus.FAIL else f"Review: {rule.title}",
                evidence=f"{rule.key}={value}; expected {rule.expected}" + (f"; {reason}" if reason else ""),
                explanation=rule.explanation,
                recommendation=rule.recommendation,
                status=status,
                severity="MEDIUM" if status is FindingStatus.FAIL else None,
            ))

    return HardeningAssessment(tuple(checks), tuple(findings))
