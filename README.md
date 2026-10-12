# Vulpnix

Vulpnix is a Linux host security assessment tool focused on **evidence-backed,
explainable results**. It separates collection, parsing, models, security rules,
findings, scan orchestration, and terminal reporting so that missing information
is never silently turned into a security conclusion.

Vulpnix targets Linux in general. Arch Linux is only the development/test
environment.

## Execution privileges

Vulpnix supports two execution modes.

### Rootless

Start normally:

```bash
vulpnix
```

The shell remains usable, but some checks may not be completely assessable.
Those checks are reported as `REVIEW` / `NOT_ASSESSED` and the final result can
be `REVIEW REQUIRED`.

Vulpnix does **not** run `sudo` internally and does not try to elevate itself.
When a check needs more access, the CLI explains that elevated privileges are
required, for example:

```text
The system could not be fully assessed with the current privileges.
Use elevated privileges to complete the missing checks: sudo vulpnix
```

### Privileged

Run Vulpnix once as root:

```bash
sudo vulpnix
```

When running directly from a source checkout, use the same model with:

```bash
sudo env PYTHONPATH=src python -m vulpnix
```

This opens the normal interactive shell as UID 0. Every command entered in that
shell inherits the same process privileges, so you do not need to type `sudo`
again:

```text
vulpnix> scan filesystem
vulpnix> scan users
vulpnix> scan ssh
vulpnix> scan
```

This is intentional: privilege elevation happens **once at process startup**,
not separately inside collectors.

## Commands

```text
help
info
version
scan
scan host
scan users
scan users --details
scan service
scan ssh
scan filesystem
clear
exit
```

`scan` runs the complete currently implemented Linux assessment. Individual
subcommands use the same scan orchestration and reporting architecture.

## Current assessment coverage

### Host

Collects hostname, distribution, OS version, kernel, architecture, and uptime.

### Services

When a service manager is available, Vulpnix collects service state and startup
enablement. A service being active is a fact, not automatically a vulnerability.

### Users and privileges

Vulpnix enumerates local accounts, UID 0 accounts, privileged accounts, login
shells, account state where available, and sudo information where it can be
reliably inspected.

Unknown or unavailable privilege information is reported for review rather than
being interpreted as safe or unsafe.

### SSH

When OpenSSH supports `sshd -G`, Vulpnix evaluates the global effective values
for root login, password authentication, empty passwords, and public-key
authentication. SSH findings are evidence-backed review/failure results rather
than a generic risk score.

Global SSH values do not replace connection-specific `Match` evaluation.

### Filesystem

The current filesystem assessment covers:

- `/etc/passwd`
- `/etc/shadow`
- `/etc/group`
- `/etc/gshadow`
- bounded SUID/SGID discovery under `/usr`, `/opt`, `/bin`, and `/sbin`

Filesystem traversal does not follow symlinks and avoids broad scans of user,
runtime, virtual, or temporary trees. Set-ID bits alone are not vulnerabilities.
A set-ID finding requires reliable evidence including an executable ELF, active
set-ID permission, world-write access, and mount options that permit execution.

The bounded discovery reports partial coverage when permission, mount, time, or
entry limits prevent complete inspection.

## Result semantics

Vulpnix currently uses three final result states:

- **NO VERIFIED ISSUES** — no verified failing finding and complete coverage.
- **REVIEW REQUIRED** — no verified failing finding, but one or more checks could
  not be completed reliably.
- **ISSUES DETECTED** — one or more security conditions were reliably verified.

`REVIEW`, `NOT_ASSESSED`, and `ERROR` are **not vulnerabilities**.

No aggregate risk score is implemented yet. Risk scoring is intentionally
reserved for a later milestone.

## Architecture

```text
CLI shell
   │
   ▼
ScanOrchestrator
   │
   ├── ScanProgress
   │
   ├── Collectors ── Parsers ── Models
   │                         │
   │                         ▼
   │                       Rules
   │                         │
   │                         ▼
   │                      Findings
   │
   └── ScanResult
            │
            ▼
       Terminal Report
            │
            ▼
        Final Result
```

Collectors do not own terminal presentation. The orchestrator emits lifecycle
progress, and the renderer consumes normalized scan results.

## Security design principles

- Treat system data and command output as untrusted input.
- Use argument-list subprocess calls with `shell=False`.
- Do not automatically elevate privileges.
- Elevation is chosen by the user at process startup.
- Never interpret unavailable information as `PASS` or `FAIL`.
- Do not follow filesystem symlinks during security-sensitive traversal.
- Bound expensive filesystem discovery.
- Sanitize terminal-visible external data.
- Keep facts, assessment status, severity, exposure, and risk conceptually
  separate.

## Development

The project uses a `src/` layout. From the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The development environment is Linux/Arch, but implementation decisions should
remain portable across Linux distributions.

## Roadmap

M1 Foundation, M2 Host & SSH, M3 Users & Privileges, and M4 Filesystem Security
are complete. The next development milestone is **M5 — Network Exposure**.
