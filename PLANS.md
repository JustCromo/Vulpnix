# Vulpnix Development Roadmap

This document is the source of truth for Vulpnix's long-term plan. Update it
when a milestone's status or objectives materially change.

## Project and principles

Vulpnix is a modular Linux security assessment tool. It collects system
information, normalizes it, evaluates security configuration, produces
explainable findings, and eventually evaluates associated risk.

> Vulpnix should prefer not to give an answer rather than give a wrong answer.

Arch Linux is only the development/test environment; Vulpnix targets Linux in
general. Keep distribution-specific behavior isolated behind detection and
adapters. Unsupported capabilities are explicit and never interpreted as secure.

Intended pipeline:

```text
Vulpnix shell → Collectors → Parsers → Models → Rules → Findings → Risk Engine → Reporters
Packages → separate CVE Engine → CVE Findings
```

Collectors collect; parsers normalize; models represent normalized data; rules
evaluate security conditions; findings explain detected issues; risk is
evaluated separately; rendering is separate from assessment logic. Collection
facts are not automatically vulnerabilities. Missing information is never
PASS or FAIL.

### Status and exposure

- **PASS:** the secure condition was checked and reliably verified.
- **FAIL:** an insecure condition was reliably verified.
- **NOT_ASSESSED:** reliable information was insufficient. It is not a
  vulnerability and must not affect risk score.
- **ERROR:** the check failed unexpectedly.

Unsupported functionality, unavailable commands, missing optional capabilities,
and parsing failures must not automatically be treated as secure or insecure.
Exposure values are **LOCAL**, **NETWORK**, **EXTERNAL**, and **UNKNOWN**.
Exposure, severity, and status are separate concepts.

### Normalized models

- **SystemInfo:** hostname, distribution, version, kernel, architecture, uptime
- **User:** username, uid, gid, groups, shell, privileged
- **Package:** name, version, architecture, manager, repository, source
- **Service:** name, state, enabled, pid, source
- **NetworkEndpoint:** protocol, address, port, state, process, service
- **FileMetadata:** path, owner, group, mode, size, type
- **Finding:** id, category, title, status, severity, evidence, explanation,
  impact, recommendation, references

### Security constraints

- Treat system data as untrusted: `/proc`, `/sys`, `/etc`, command output,
  package metadata, journals, external CVE data, and user-supplied paths/args.
- Use safe subprocess APIs such as `subprocess.run([...], shell=False)`; never
  construct shell commands by string concatenation.
- Do not require root by default. Make privilege needs explicit; if required
  privileges are unavailable, report unavailable/NOT_ASSESSED.
- Protect terminal output against ANSI/control-sequence injection; validate
  parser inputs; handle filesystem permissions and symlinks safely; protect
  baseline, cache, and configuration data.

## Milestones

### M1 — Foundation

**Status: COMPLETE**

**Purpose:** Establish the basic architecture and interactive CLI.

**Objectives:** Create the Python project/package; implement interactive shell,
`vulpnix`, `help`, `exit`, `clear`, `version`, initial `scan`; separate CLI,
collectors, parsers, and models; establish structured errors, Linux-general
design, Git/GitHub, automated tests, and readable terminal UI.

**Expected architecture:** `src/vulpnix/{__init__.py,__main__.py,cli/,collectors/,models/,parsers/}`.

**Completion criteria:** Vulpnix starts in a terminal; shell and basic commands
work; scan works; project is modular; tests run; Git repository is functional.

### M2 — Host & SSH Security Assessment

**Status: COMPLETE**

**Purpose:** Implement the first Linux security assessment capabilities.

**Objectives:**

- System: detect hostname, distribution, OS version, kernel, architecture, and
  uptime; keep collection separate from security assessment.
- Services: detect services where a manager is available; identify active and
  enabled services; distinguish active/installed/unknown; isolate systemd
  behavior and detect its availability.
- SSH: detect availability; validate configuration; determine effective
  configuration; check root login, password authentication, empty passwords,
  and public-key authentication; handle missing `sshd -G`; do not require sudo
  for normal assessment; do not turn configuration facts directly into
  vulnerabilities.
- `sshd -C` contextual evaluation may be an advanced/internal capability; normal
  user commands remain `vulpnix> scan` and `vulpnix> scan ssh`.

**Expected deliverables:** Host/service/SSH collection, normalized data,
explainable findings, and readable output.

**Completion criteria:** Host assessment works; service inventory works where
supported; SSH assessment works where supported; unsupported capability is
unavailable/NOT_ASSESSED; findings contain evidence; important parsing and
failure cases are tested.

### M3 — Users & Privileges

**Status: NEXT**

**Purpose:** Assess Linux users, privileged accounts, and privilege-related
security configuration.

**Objectives:** Enumerate local users and UID 0 accounts; detect privileged
groups and sudo access where reliably available; collect login shells and account
state where reliable; distinguish ordinary users from system/service accounts;
identify elevated accounts and verifiable dangerous privilege assignments; work
with incomplete data and systems without sudo. Do not assume every UID 0 account
is vulnerable, sudo exists, group names are universal, or a specific
distribution. Isolate distribution-specific behavior and prefer portable Linux
interfaces.

**Expected deliverables:** Normalized user inventory, privilege identification,
and explainable findings.

**Completion criteria:** Users are normalized; privileged accounts identifiable;
findings explainable; unsupported data is NOT_ASSESSED; tests cover ordinary,
privileged, and unsupported cases.

### M4 — Filesystem Security

**Status: PLANNED**

**Purpose:** Assess sensitive filesystem permissions and special file properties.

**Objectives:** Check ownership, group, mode, and unexpected writability of
important files using `FileMetadata`; candidate targets include `/etc/passwd`,
`/etc/shadow`, `/etc/group`, and authentication/security configuration. Detect
SUID/SGID and unusual permissions without declaring every such file vulnerable.
Detect world-writable sensitive files; later consider dangerous writable
directories/files. Handle symlinks safely and avoid an unnecessary full-filesystem
scan in the first implementation.

**Expected deliverables:** Metadata collection, sensitive-permission rules,
SUID/SGID detection, and evidence-backed recommendations.

**Completion criteria:** Collection and rules exist; findings explainable;
symlink/permission handling safe; permission edge cases tested.

### M5 — Network Exposure

**Status: PLANNED**

**Purpose:** Understand what the host exposes locally and over the network.

**Objectives:** Enumerate interfaces, addresses, and state; detect listening
TCP/UDP sockets, protocol, address, port, process/service where possible; normalize
endpoints. Distinguish `127.0.0.1:3306` from `0.0.0.0:3306` and `[::]:3306`;
classify LOCAL/NETWORK/EXTERNAL/UNKNOWN. A listening port is not automatically
vulnerable. Detect firewall implementations/state without assuming one or
treating an unavailable tool as a disabled firewall.

**Expected deliverables:** Normalized endpoints, exposure classification, and
firewall capability detection.

**Completion criteria:** Endpoints identified and normalized; exposure
classified; findings distinguish exposure from vulnerability; unsupported
firewalls handled safely; behaviors tested.

### M6 — Packages & CVE

**Status: PLANNED**

**Purpose:** Inventory installed software and correlate it with known CVEs.

**Objectives:** Detect package managers; isolate manager-specific logic; normalize
package name/version/architecture/source/manager. Detect outdated packages only
where supported; an available update is not automatically a vulnerability.
Correlate CVE, affected product/range, installed package/version,
distribution/vendor, and fix/backport status. Account for vendor backports; do
not use naive product-version-to-CVE matching. Treat external CVE data as
untrusted; validate TLS, schema, provenance, timestamps/versioning, and parsed
fields; malformed data must not create findings.

**Expected deliverables:** Package inventory and structured CVE correlation with
evidence and references.

**Completion criteria:** Managers detected; packages normalized; version ranges
and vendor backports handled; CVE findings explainable; matching and false
positive tests exist.

### M7 — Baseline & Change Detection

**Status: PLANNED**

**Purpose:** Detect meaningful changes between scans.

**Objectives:** Create a minimal normalized first-scan baseline; semantically
compare later scans for added/removed/changed/unchanged objects, not only hashes.
Consider service, listening port, package version, user, and security
configuration changes. Minimize sensitive baseline data and consider integrity.
Pass changes to assessment for interpretation; a change alone is not a security
issue.

**Expected deliverables:** Baseline format and structured semantic comparison.

**Completion criteria:** Format/comparison exist; sensitive data minimized;
integrity considered; all four change cases tested.

### M8 — Risk Engine

**Status: PLANNED**

**Purpose:** Evaluate overall risk represented by findings.

**Important:** Implement only after assessment provides enough reliable
structured findings.

**Objectives:** Aggregate findings using severity, exposure, and available
exploitability/context; distinguish confirmed failures from NOT_ASSESSED; produce
a reproducible, explainable score and overall level. Potential levels are
CRITICAL/HIGH/MEDIUM/LOW/INFO. Avoid arbitrary weights. NOT_ASSESSED must not
automatically increase risk; exposure should affect risk appropriately; findings
remain independently understandable.

**Expected deliverables:** Deterministic risk calculation, score, level, and
explanation.

**Completion criteria:** Calculation is deterministic and explainable; status and
exposure are handled appropriately; scoring tests exist.

### M9 — Reporting & Release

**Status: PLANNED**

**Purpose:** Make Vulpnix polished and distributable.

**Objectives:** Keep assessment separate from reporters consuming structured
data. Plan Terminal, JSON (stable automation schema), Markdown, and professional
HTML reports. Keep interactive shell and readable output; retain single-column
terminal layout unless a future design proves a better one; avoid broken wrapping
and duplicate findings. Complete documentation for installation, usage,
architecture, security model, Linux capabilities, limitations, and examples.
Address threat model, subprocess safety, input validation, terminal
sanitization, filesystem safety, external data validation, and least privilege.
Cover unit, parser, collector failure, rule, integration, CLI, and regression
tests. Prepare a clean versioned GitHub release with no debug code, secrets, or
accidental personal data and complete documentation.

**Expected deliverables:** Terminal/JSON/Markdown/HTML reporters, complete docs
and security model, comprehensive tests, and a release.

**Completion criteria:** Another user can use Vulpnix as a Linux security
assessment tool without understanding its internal implementation.

## Final V1 architecture

```text
Vulpnix Core
├── Collectors
├── Parsers
├── Models
├── Rules
├── Findings
├── Risk Engine
├── Baseline Engine
├── CVE Engine
└── Reporters (Terminal, JSON, Markdown, HTML)
```

## Roadmap status

| Milestone | Name | Status |
|---|---|---|
| M1 | Foundation | COMPLETE |
| M2 | Host & SSH Security Assessment | COMPLETE |
| M3 | Users & Privileges | NEXT |
| M4 | Filesystem Security | PLANNED |
| M5 | Network Exposure | PLANNED |
| M6 | Packages & CVE | PLANNED |
| M7 | Baseline & Change Detection | PLANNED |
| M8 | Risk Engine | PLANNED |
| M9 | Reporting & Release | PLANNED |

## Working rules

1. Do not skip milestones without explicitly discussing why.
2. Do not implement future milestones prematurely.
3. Complete the current milestone before moving to the next.
4. Before a milestone, inspect the architecture and propose a design.
5. Prefer small incremental changes; do not blindly generate large amounts of
   code.
6. Preserve Linux-general support and the distinction between facts, findings,
   status, severity, and exposure.
7. Never turn missing information into a security conclusion.
8. Update this roadmap when status/objectives materially change.

**Current next milestone: M3 — Users & Privileges.**

