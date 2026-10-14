"""Documented default risk profiles for verified Linux findings.

Impact and probability are qualitative 1-5 assessments for a general
Linux-host threat model. Probability is not a statistical probability.
Profiles are intentionally limited to findings whose conditions describe
a sufficiently concrete security weakness.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RiskProfile:
    impact: int
    probability: int
    rationale: str


DEFAULT_PROFILES: dict[str, RiskProfile] = {
    "FS-SENSITIVE-OWNER-001": RiskProfile(
        impact=5,
        probability=4,
        rationale=(
            "Impact 5: unauthorized control of a sensitive account or "
            "authentication file can enable serious account compromise. "
            "Probability 4: an incorrectly owned file gives its owner a "
            "potential path to modify security-critical data, although "
            "local access and the exact file permissions still matter."
        ),
    ),
    "FS-SENSITIVE-WRITE-001": RiskProfile(
        impact=5,
        probability=4,
        rationale=(
            "Impact 5: unauthorized modification of a sensitive account "
            "or authentication file can compromise system accounts. "
            "Probability 4: group or other write access creates a concrete "
            "local modification opportunity, subject to the effective "
            "permissions and the attacker's access."
        ),
    ),
    "FS-SECRET-WORLD-READ-001": RiskProfile(
        impact=4,
        probability=4,
        rationale=(
            "Impact 4: world-readable password-hash material can support "
            "offline guessing and reuse attacks, but does not itself prove "
            "that a password can be recovered. Probability 4: every local "
            "user can read the material when the reported permissions "
            "apply, while successful exploitation depends on password "
            "strength and other circumstances."
        ),
    ),
    "FS-SETID-WORLD-WRITE-001": RiskProfile(
        impact=5,
        probability=5,
        rationale=(
            "Impact 5: a world-writable executable with set-ID permissions "
            "and an executable filesystem can provide a direct route to "
            "privilege escalation. Probability 5: the finding identifies "
            "the combination of conditions that makes modification of "
            "that executable a concrete local attack path."
        ),
    ),
    "SYSTEMD-UNIT-METADATA-001": RiskProfile(
        impact=5,
        probability=4,
        rationale=(
            "Impact 5: unauthorized modification of a privileged service "
            "definition can lead to code execution with that service's "
            "privileges when the unit is started or reloaded. Probability "
            "4: unsafe ownership or write permissions create a plausible "
            "modification path, but exploitation depends on the unit and "
            "when it is executed."
        ),
    ),
    "KERNEL-HARDENING-KERNEL-DMESG-RESTRICT": RiskProfile(
        impact=3,
        probability=3,
        rationale=(
            "Impact 3: access to kernel logs can disclose diagnostic or "
            "system details useful during further attacks, but does not "
            "by itself compromise the host. Probability 3: exposed logs "
            "may help a local attacker when useful information is present."
        ),
    ),
    "KERNEL-HARDENING-KERNEL-KPTR-RESTRICT": RiskProfile(
        impact=3,
        probability=3,
        rationale=(
            "Impact 3: exposed kernel pointers can make some kernel "
            "exploitation techniques easier, but are not a vulnerability "
            "or compromise by themselves. Probability 3: the setting can "
            "reduce an information barrier for a local attacker when a "
            "separate exploitable kernel weakness exists."
        ),
    ),
    "KERNEL-HARDENING-FS-PROTECTED-HARDLINKS": RiskProfile(
        impact=3,
        probability=2,
        rationale=(
            "Impact 3: missing hard-link protections can weaken a defence "
            "against certain unsafe link scenarios involving files the "
            "attacker cannot otherwise modify. Probability 2: exploitation "
            "requires suitable target files and additional local "
            "preconditions; the setting alone does not establish a path "
            "to compromise."
        ),
    ),
    "KERNEL-HARDENING-FS-PROTECTED-SYMLINKS": RiskProfile(
        impact=4,
        probability=2,
        rationale=(
            "Impact 4: missing symbolic-link protections can contribute "
            "to link-following attacks against privileged processes. "
            "Probability 2: a useful target, vulnerable operation, and "
            "appropriate timing or access are also required."
        ),
    ),
    "KERNEL-HARDENING-NET-IPV4-CONF-ALL-ACCEPT-SOURCE-ROUTE": RiskProfile(
        impact=3,
        probability=2,
        rationale=(
            "Impact 3: accepting IPv4 source-routed packets can weaken "
            "network trust assumptions and assist certain traffic-routing "
            "attacks. Probability 2: practical exploitation depends on "
            "network reachability, kernel behaviour, and the surrounding "
            "network controls."
        ),
    ),
    "KERNEL-HARDENING-NET-IPV4-CONF-DEFAULT-ACCEPT-SOURCE-ROUTE": RiskProfile(
        impact=3,
        probability=2,
        rationale=(
            "Impact 3: accepting IPv4 source-routed packets by default "
            "can weaken network trust assumptions and assist certain "
            "traffic-routing attacks. Probability 2: practical exploitation "
            "depends on interface configuration, network reachability, "
            "kernel behaviour, and other controls."
        ),
    ),
}
