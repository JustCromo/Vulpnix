# Vulpnix Development Roadmap

This document is the source of truth for the project's milestones and design
constraints. The acceptance criteria in [QUALITY.md](QUALITY.md) are mandatory
for every milestone.

## Core principles

Vulpnix is a modular Linux security assessment tool. It collects system facts,
normalizes them, evaluates security conditions, produces explainable findings,
and will later provide separate risk, CVE, baseline, and reporting engines.

> Prefer not to give an answer rather than give a wrong answer.

Linux is the target platform. Distribution-specific behavior must remain inside
capability detection or adapters.

Collection facts are not automatically vulnerabilities. Missing information is
never `PASS` or `FAIL`.

### Finding statuses

- `PASS` — the secure condition was reliably checked.
- `FAIL` — an insecure condition was reliably verified.
- `REVIEW` — context or manual review is required.
- `NOT_ASSESSED` — reliable evidence was unavailable.
- `ERROR` — the check failed unexpectedly.

`REVIEW`, `NOT_ASSESSED`, and `ERROR` do not become vulnerabilities and do not
receive an artificial risk impact.

## Privilege model

Vulpnix supports both rootless and privileged execution.

```text
vulpnix                    → ROOTLESS
sudo vulpnix               → PRIVILEGED / UID 0
```

The application does not invoke `sudo` internally. Once the process starts as
UID 0, every command in the interactive shell inherits the same privileges.
Collectors therefore remain privilege-agnostic and simply report what they can
or cannot assess.

Rootless incomplete coverage must result in `REVIEW REQUIRED` with an explicit
instruction to rerun Vulpnix with elevated privileges. Privilege level changes
collection capability; it does not change the underlying security rules.

## Shared scan architecture

All scan commands use the same lifecycle:

```text
ScanOrchestrator
      │
      ├── STARTING
      ├── COLLECTING
      ├── ASSESSING
      ├── COMPLETED / ERROR
      │
      ▼
  ScanResult
      │
      ▼
 Detail Renderer
      │
      ▼
 Final Result
```

`ScanProgress` is emitted by the orchestrator while work is actually running.
The terminal CLI displays live progress in interactive mode and remains
usable in non-interactive/test environments.

## Milestone and qualification status

`Implementation status` describes whether the planned functionality has been
built. `Quality qualification` describes whether that functionality has passed
the acceptance gate in `QUALITY.md`. These statuses are separate; implementation
completion alone does not establish qualification.

M1–M4 and M4.5 are implementation-complete, but their retrospective quality
qualification is **PENDING REVIEW**. The initial M5 implementation is now being
built in parallel at the user's request; this does not waive the acceptance gate
for qualification or release. This is a verification gate, not an assumption
that existing implementations are defective.

## Milestones

### M1 — Foundation

**Status: COMPLETE**

**Quality qualification: PENDING REVIEW**

Interactive shell, package structure, basic commands, Linux-general design,
initial testing, and terminal foundations.

### M2 — Host & SSH Security Assessment

**Status: COMPLETE**

**Quality qualification: PENDING REVIEW**

Host facts, service inventory, OpenSSH effective configuration, SSH rules,
portable capability handling, and SSH parsing/failure tests.

### M3 — Users & Privileges

**Status: COMPLETE**

**Quality qualification: PENDING REVIEW**

Local users, UID 0 accounts, privileged accounts, sudo inspection, account state,
group information, review semantics, and adversarial tests.

### M4 — Filesystem Security

**Status: COMPLETE**

**Quality qualification: PENDING REVIEW**

Sensitive file metadata assessment for authentication/security files, safe
symlink handling, ownership/mode checks, bounded SUID/SGID discovery, ELF
verification, mount-option checks, partial-coverage reporting, and adversarial
tests.

The milestone is considered complete without adding an aggregate risk score.

### M4.5 — Scan Architecture & CLI UX

**Status: COMPLETE**

**Quality qualification: PENDING REVIEW**

Shared scan orchestration, normalized `ScanResult`, lifecycle progress,
consistent individual/full scan behavior, privilege context, rootless review
messaging, readable single-column terminal reporting, final-result rendering,
updated logo, documentation, and architecture tests.

### M5 — Network Exposure

**Status: IN PROGRESS — initial socket inventory implemented**

**Quality qualification: PENDING REVIEW**

**Purpose:** understand what the Linux host exposes locally and over the network.

Initial implementation now includes:

- Listening TCP and bound UDP socket inventory via `ss`, with a `/proc/net`
  fallback when `ss` is unavailable or unusable.
- Normalized protocol/address/port/state and loopback/non-loopback/all-interface
  bind scope.
- Best-effort process ownership attribution; incomplete attribution results in
  partial coverage rather than a false claim of completeness.
- Selected kernel-hardening `sysctl` checks.
- Metadata-only assessment of SSH host private-key files and systemd service
  unit fragments/drop-ins.
- Compact default terminal output plus expanded output with `--details`.

Remaining M5 objectives:

- Enumerate network interfaces, IP addresses, and operational state.
- Detect firewall implementations and collect their configured state safely.
- Keep bind scope distinct from claims about internet reachability.
- Never interpret a listening port alone as a vulnerability.
- Preserve rootless/privileged coverage semantics across commands and full scan.

The implemented socket inventory is an initial M5 component, not a complete
network-exposure or firewall assessment. Expected deliverables include stable
normalized interface/socket/firewall observations, explainable rules, and tests
for IPv4/IPv6, loopback/all-interface exposure, unavailable tools, and permission
limits.

### M6 — Packages & CVE

**Status: PLANNED**

Detect package managers, normalize packages, and correlate versions with CVEs
while accounting for vendor backports and external-data validation.

### M7 — Baseline & Change Detection

**Status: PLANNED**

Create a minimal normalized baseline and semantically detect added, removed,
changed, and unchanged objects without treating change itself as a vulnerability.

### M8 — Risk Engine

**Status: PLANNED**

Add deterministic, explainable risk aggregation only after enough structured
findings exist. `NOT_ASSESSED` must never be converted into risk merely because
information is missing.

### M9 — Reporting & Release

**Status: PLANNED**

Terminal/JSON/Markdown/HTML reporters, stable documentation, security model,
release hygiene, and comprehensive regression/integration testing.

## Final V1 architecture

```text
Vulpnix Core
├── Collectors
├── Parsers
├── Models
├── Rules
├── Findings
├── Scan Orchestrator
├── Risk Engine
├── Baseline Engine
├── CVE Engine
└── Reporters
    ├── Terminal
    ├── JSON
    ├── Markdown
    └── HTML
```

## Working rules

1. Complete the current milestone before moving to the next.
2. Do not silently skip security checks because data is inconvenient to obtain.
3. Preserve Linux-general behavior.
4. Keep collection, assessment, findings, risk, and rendering separate.
5. Never turn missing information into a security conclusion.
6. Keep privilege elevation outside collectors; the user chooses root at startup.
7. Prefer small, testable changes and adversarial tests.
8. Run the full test suite and `git diff --check` before milestone completion.

**Current focus: retroactive quality qualification for M1–M4 and M4.5.**
M5 implementation starts after the initial review is recorded.
