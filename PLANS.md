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
qualification is **PENDING REVIEW**. M5 implementation is actively in progress.
Socket and interface inventories, read-only firewall collection, and preliminary
firewall-policy analysis are implemented, but the remaining M5 work and its
acceptance criteria have not all been completed. This does not waive the
acceptance gate for qualification or release.

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

**Implementation status: COMPLETE**

**Quality qualification: PENDING REVIEW**

Implemented and exercised:
- Listening TCP and bound UDP socket inventory, with process attribution where available.
- Network interface and IP-address inventory.
- Read-only nftables, iptables-save and ip6tables-save collection.
- Conservative, bounded analysis of supported firewall input and forwarding policies.
- Explicit handling of unavailable tools, command failures, timeouts and malformed data.
- Integration in individual and full assessments, with rootless and privileged runtime checks.

Known limitations accepted for delivery:
- Firewall semantics are not fully resolved across every chain, hook and backend.
- Some layouts, including the tested libvirt forwarding chains, cannot support a complete inbound-policy conclusion.
- These cases remain REVIEW; socket visibility and permissive forwarding policies alone do not prove internet reachability or a vulnerability.

Further firewall analysis is follow-up work unless a concrete blocking defect is discovered.

### M6 — Packages & CVE

**Status: IN PROGRESS — initial implementation and Arch runtime test completed**

**Quality qualification: PENDING REVIEW**

**Purpose:** inventory installed software and correlate installed versions with
distribution-aware vulnerability advisories without silently treating missing
or inconclusive evidence as secure or vulnerable.

Implemented:

- Read-only installed-package inventory adapters for `pacman`, `dpkg-query`,
  `rpm`, and `apk`, with normalized package name, version, and architecture.
- Distribution detection from `/etc/os-release`, parsed as data rather than
  executed as shell code.
- Arch Linux advisory lookup through the official Security Tracker dataset.
- OSV batch-query integration for the explicitly mapped ecosystems implemented
  in the current code: Debian, Ubuntu, Alpine, AlmaLinux, and Rocky Linux.
- Explicitly unsupported or unmapped ecosystems remain unavailable or
  unassessed; the code does not guess an OSV ecosystem merely from `rpm`.
- Remote advisory correlation runs by default for `scan packages` and is
  included in `scan`. These checks query supported remote sources and require
  network access. Unavailable sources or unsupported ecosystems must remain
  incomplete or unassessed rather than being treated as secure.

- Evidence records identify the installed package/version, advisory source,
  source status, available affected/fixed versions, and the reason for `FAIL`
  or `REVIEW`.
- For Arch advisories without a fixed version, a package version newer than the
  advisory's affected-version threshold is marked `REVIEW`, not automatically
  counted as a confirmed vulnerability. An unavailable version comparison is
  also inconclusive.
- Risk scores are restricted to findings that meet the existing verified-FAIL
  and complete-risk-profile criteria.

**Runtime validation performed:**

- The Arch Linux development host returned 844 installed package records using
  `pacman`, with inventory status `OK`.
- The official Arch advisory feed returned 18 matching advisory records in the
  recorded run. All 18 required `REVIEW` because the installed versions compared
  newer than the listed affected versions while no fixed version was provided.
- That result validates the conservative handling of those records; it does
  not prove that the host has no package vulnerabilities.
- The regression suite covers stale Arch advisory states, including newer,
  equal, older, and incomparable installed versions.

Remaining objectives:

- Further validate source-state handling and affected/fixed-version semantics
  against current real advisory records, including records with a fixed version.
- Validate OSV package naming, ecosystem mapping, and range handling against
  the actual supported distributions and their vendor package conventions.
- Expand integration testing beyond the current Arch development host.
- Keep unsupported sources, failed network requests, and ambiguous results
  explicitly visible in the final assessment.
- Complete the mandatory `QUALITY.md` acceptance process before claiming
  release-level qualification.

A package with no matching advisory is not thereby proven secure. Vendor
backports, upstream version differences, stale advisories, and incomplete
source coverage remain material limitations.

### M7 — Disk & Filesystem Assessment

**Status: IMPLEMENTED — INITIAL**

**Quality qualification: PENDING**

The initial disk/filesystem assessment is integrated into `scan filesystem`
and the full `scan`. It collects mounted-filesystem metadata, capacity and
available bytes, inode information, filesystem types, mount points, and
relevant mount options. Conservative rules flag selected low-capacity,
low-inode, and temporary-filesystem mount-option conditions for `REVIEW`.
These results are not, by themselves, proof of exploitability.

The automated tests have passed in the current development checkout.
Cross-distribution runtime coverage, rootless/privileged behavior, and
known-good/known-bad scenarios in a controlled Linux VM remain required by
`QUALITY.md`. Unknown or unavailable measurements are not interpreted as
secure or insecure.

Existing sensitive-file metadata and bounded set-ID checks remain part of M4.

### M8 — Risk Engine

**Status: IMPLEMENTED — INITIAL PER-FINDING SCORING**

**Quality qualification: PENDING**

The risk engine assigns a qualitative score to eligible individual findings
using Impact (1–5) × Probability (1–5), with documented rationale and the
existing LOW, MODERATE, HIGH, and CRITICAL bands.

Only verified `FAIL` findings with a complete, valid risk profile are scored.
`PASS`, `REVIEW`, `NOT_ASSESSED`, and `ERROR` are excluded. Verified failures
without a complete valid profile remain explicitly unscored. Package/CVE
findings may provide an explicit risk profile when sufficient evidence is
available.

An observed host/scan-scope risk score uses the maximum eligible per-finding
score among verified `FAIL` findings with complete risk profiles; it is not a sum.
The score is 0/25 when no eligible finding is scored. Unscored verified failures
and incomplete coverage are reported separately. Missing evidence must never be
converted into either risk or reassurance; targeted scans score only their scope.

The recent automated test run passed, including risk-engine and risk-profile
coverage tests. This does not replace the acceptance checks in `QUALITY.md`.

### M9 — Reporting, CLI UX & Release

**Status: IN PROGRESS**

**Quality qualification: PENDING REVIEW**

A first-pass inspection has traced the CLI entry points, shared report model,
summary builder, terminal helpers, and full-scan assembly. The complete
command/handler/completion/test review and a documented refactoring
plan are still required before coordinated changes to the interface.

#### Phase 1 — Full project review and command consolidation

Review the complete source checkout, including source modules, collectors,
parsers, models, rules, tests, CLI modules, `pyproject.toml`, `README.md`,
`PLANS.md`, and `QUALITY.md`.

Before changing code:

- Map the actual command entry points, flags, completions, handlers, and their
  shared or duplicated behavior.
- Trace how section results, findings, coverage, privileges, and risk data
  currently reach the renderer.
- Identify duplicate command paths, inconsistent option behavior, repeated
  report content, unclear user actions, and status messages that can be
  misleading to a non-technical user.
- Produce one coherent command contract and a refactoring plan before making
  coordinated changes across the CLI.

The goal is to reduce redundant command variants while preserving a clear
distinction between a complete local assessment, targeted section scans,
optional detail output, and explicitly requested remote advisory queries.
The exact final command vocabulary will be decided after the full-tree review,
rather than adding further aliases piecemeal.

#### Phase 2 — Clear default terminal output

The ordinary scan must be understandable without security engineering
experience. All user-facing text remains in English.

Planned default report structure:

1. A compact header showing the host, execution mode, and assessment scope.
2. A short overall status with counts of verified issues, items requiring
   review, and checks that could not be completed.
3. A section summary in a stable order, using simple tables and visible
   separators that adapt to the terminal width.
4. A final **FINAL REVIEW / NEXT ACTIONS** section grouping concrete problems
   by area, such as SSH, network, services, filesystem, and packages.
5. For each area needing attention, explain what was observed, why it matters,
   whether it is verified or uncertain, and what the user should do next.
6. Omit healthy sections from the final review rather than listing every
   successful low-level check.

`--details` remains the way to request expanded evidence, individual checks,
source references, rule identifiers, and technical diagnostics. It must not
change the security assessment itself.

#### Phase 3 — Structured results and regression coverage

- Reuse structured section and finding data for the final review instead of
  parsing terminal text.
- Associate findings and incomplete coverage with stable assessment categories
  so the final review can summarize the relevant sections accurately.
- Avoid duplicating every finding in several parts of the default output.
- Keep distinct states for verified findings, review items, unavailable checks,
  and unexpected errors. Missing evidence must never be rendered as a pass.
- Make rootless and privileged runs clear and actionable, explaining what
  could not be assessed and when elevated privileges would help.
- Add tests for report ordering, omitted healthy sections, actionable review
  summaries, narrow terminal widths, command dispatch, rootless/privileged
  coverage, and detail-mode behavior.
- Preserve the existing risk scoring rules and prevent report presentation
  changes from modifying assessment results.

#### Phase 4 — Report formats and release readiness

Once the terminal report and structured review are coherent, evaluate JSON,
Markdown, and HTML report outputs. Keep rendering separate from collection,
rules, and risk calculation.

Run the complete suite, verify source-checkout usage from the README, exercise
rootless and privileged runtime paths, review release hygiene, and complete the
quality acceptance gates defined in `QUALITY.md`.

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

**Current focus: M9 — Reporting, CLI UX & Release.** M6 package/CVE correlation, M7 disk/filesystem assessment, and M8 per-finding risk scoring have initial implementations. Formal quality qualification remains pending. Package advisory coverage still needs further validation. Host-wide risk aggregation, baseline/change detection, and report export formats remain deferred or planned.
