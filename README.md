# Vulpnix

Vulpnix is a Linux host security assessment tool focused on **evidence-backed,
explainable results**. It separates collection, parsing, models, security rules,
findings, orchestration, and terminal reporting so missing information is never
silently turned into a security conclusion.

Linux is the target platform. Arch Linux is the development environment, not the
only intended distribution. Cross-distribution compatibility still needs
validation on real Linux systems before it can be claimed.

## Run with or without root

### Rootless

```bash
vulpnix
```

The shell remains usable. When a check cannot be completed reliably, Vulpnix
reports `REVIEW`, `NOT_ASSESSED`, or `ERROR` and the final result can be
`REVIEW REQUIRED`. Missing privileges or unavailable commands are not treated as
a successful check.

### Privileged

```bash
sudo vulpnix
```

For a source checkout:

```bash
sudo env PYTHONPATH=src python -m vulpnix
```

This opens one interactive shell as UID 0. Every command entered in that shell
inherits the same process privileges, so you do not prefix individual scans
with `sudo`. Vulpnix never elevates itself or runs `sudo` internally.

Root can enable deeper inspection of process ownership, SSH host-key metadata,
and system service unit metadata where the host's capabilities permit it. It
does not make every check automatically complete: unsupported tools, failed
commands, malformed output, resource limits, and missing evidence still need to
be reported.

## Commands

```text
help
info
version
scan [--details]
scan host [--details]
scan hardening [--details]
scan network [--details]
scan users [--details]
scan service [--details]
scan ssh [--details]
scan filesystem [--details]
clear
exit
```

The default output is a concise summary: key facts, findings requiring
attention, and a final result. `--details` expands check-level evidence or
inventories where available; it does not change the security rules.

### What the checks do

- **`scan`** runs the currently implemented full assessment: host facts, service
  inventory, local accounts and privileges, filesystem metadata and bounded
  SUID/SGID discovery, global SSH configuration, selected kernel-hardening
  parameters, local listening/bound sockets, SSH host-key metadata, and
  systemd unit/drop-in metadata.
- **`scan host`** reports hostname, distribution, kernel, architecture, and
  uptime. `scan host --details` also includes selected kernel-hardening checks.
- **`scan hardening`** reads a fixed allow-list of kernel `sysctl` parameters in
  read-only mode. Context-dependent values are marked for review rather than
  automatically treated as vulnerabilities.
- **`scan network`** inventories listening TCP and bound UDP sockets, their
  address/port and bind scope, and process attribution where available. It uses
  `ss` when usable and falls back to `/proc/net` when possible. A bind address is
  not proof that a service is reachable from the internet. Firewall-policy and
  interface-address assessment remain future work; this command is not yet a
  complete network-exposure assessment.
- **`scan service`** summarizes service state and startup enablement.
  `scan service --details` additionally checks metadata for systemd unit
  fragments and drop-ins. File contents are not read.
- **`scan ssh`** checks selected global `sshd` options and inspects SSH host
  private-key path/type/owner/mode metadata. Private-key contents are never
  opened or read. `--details` lists each metadata check.
- **`scan users`** reviews local accounts, UID 0 accounts, privileged users,
  and sudo information where it can be reliably inspected. `--details` shows
  the full account inventory.
- **`scan filesystem`** inspects metadata for `/etc/passwd`, `/etc/shadow`,
  `/etc/group`, `/etc/gshadow` and performs bounded SUID/SGID discovery under
  `/usr`, `/opt`, `/bin`, and `/sbin`. Traversal does not follow symlinks and
  avoids broad scans of user, runtime, virtual, or temporary trees. A set-ID bit
  alone is not a vulnerability; verified findings require evidence including
  executable ELF content, active set-ID permissions, world-write access, and
  mount options that permit execution.

## Result semantics

- **NO VERIFIED ISSUES** — no verified failing finding and coverage is complete.
- **REVIEW REQUIRED** — one or more checks need review or could not be completed
  reliably.
- **ISSUES DETECTED** — one or more insecure conditions were verified by the
  relevant rule criteria.

`REVIEW`, `NOT_ASSESSED`, and `ERROR` are not confirmed vulnerabilities. A
listening port, active service, non-default setting, or SUID/SGID bit is not by
itself proof of a vulnerability. No aggregate risk score or CVE engine is
implemented yet.

## Architecture

```text
CLI shell
   │
   ▼
ScanOrchestrator ── ScanProgress
   │
   ├── Collectors ── Parsers ── Models
   │                         │
   │                         ▼
   │                       Rules
   │                         │
   │                         ▼
   │                      Findings
   ▼
ScanResult ── Terminal report ── Final result
```

Collectors are read-only, use argument-list subprocess calls with `shell=False`,
and apply timeouts to external commands. The terminal renderer does not collect
or assess data itself.

## Development and tests

Create a virtual environment if you do not have `pip` in the system Python, then
install the package from the project root:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --no-deps .
```

Run the automated suite from a source checkout:

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -v
```

Passing unit tests are necessary but not sufficient to establish real-world
reliability. The quality acceptance criteria in [QUALITY.md](QUALITY.md) require
known-good/known-bad scenario validation in a controlled Linux VM, as well as
rootless and privileged runtime checks and cross-distribution testing before
release claims are made.

## Roadmap

See [PLANS.md](PLANS.md). Network socket visibility, selected kernel hardening,
SSH host-key metadata, and systemd unit metadata are now implemented as an
initial expansion. Interface inventory, firewall-policy analysis, package/CVE
correlation, baseline/change detection, risk aggregation, and additional report
formats remain planned work.
