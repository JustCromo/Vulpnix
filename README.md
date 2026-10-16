# Vulpnix

Vulpnix is a Linux host security assessment tool focused on **evidence-backed,
explainable results**. It separates collection, parsing, models, security rules,
findings, orchestration, and terminal reporting so missing information is never
silently turned into a security conclusion.

Linux is the target platform. Arch Linux is the development environment, not the
only intended distribution. Cross-distribution compatibility still needs
validation on real Linux systems before it can be claimed.

## Installation

Vulpnix is a Python command-line application installed with
[pipx](https://pipx.pypa.io/). Choose a system-wide installation if you need
to run privileged scans with `sudo vulpnix`, or a per-user installation for
rootless use.

### 1. Install pipx and Git

Arch Linux:

```bash
sudo pacman -S python-pipx git
```

Debian or Ubuntu:

```bash
sudo apt update
sudo apt install pipx git
```

Fedora:

```bash
sudo dnf install pipx git
```

For other distributions or installation methods, follow the
[official pipx installation guide](https://pipx.pypa.io/latest/how-to/install-pipx.html).

### 2. System-wide installation

The following commands use explicit pipx paths instead of the `--global`
option. This supports pipx versions that do not recognize `--global`.

Install Vulpnix from the public GitHub repository:

```bash
sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin PIPX_MAN_DIR=/usr/local/share/man pipx install 'git+https://github.com/JustCromo/Vulpnix.git'
```

Update the installation after a new version has been pushed:

```bash
sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin PIPX_MAN_DIR=/usr/local/share/man pipx upgrade vulpnix
```

Uninstall Vulpnix:

```bash
sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin PIPX_MAN_DIR=/usr/local/share/man pipx uninstall vulpnix
```

Use the same paths for installation, upgrade, and uninstall. These commands
assume that `pipx` is installed and available to `sudo`. The executable is
placed in `/usr/local/bin`, normally available to regular users and `sudo`.

### 3. Per-user installation (rootless use)

For an installation limited to the current user:

```bash
pipx install 'git+https://github.com/JustCromo/Vulpnix.git'
pipx ensurepath
```

Open a new terminal if `pipx ensurepath` updates your PATH. On many Linux
systems, the per-user executable directory is `~/.local/bin`.

A per-user installation is suitable for rootless use. Do not assume that
`sudo` can find this installation: `sudo` may use a different PATH, and
running user-writable application code as root is not recommended. Use the
system-wide installation above for privileged scans.

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
scan [--details] [--format html|markdown|json]
scan host [--details] [--format html|markdown|json]
scan hardening [--details] [--format html|markdown|json]
scan network [--details] [--format html|markdown|json]
scan users [--details] [--format html|markdown|json]
scan service [--details] [--format html|markdown|json]
scan ssh [--details] [--format html|markdown|json]
scan filesystem [--details] [--format html|markdown|json]
scan packages [--details] [--format html|markdown|json]
clear
exit
```

`scan` runs the full implemented assessment, including package inventory and
CVE/advisory correlation. `scan packages` runs the package inventory and
vulnerability audit on their own. Remote advisory checks require network access.
Unavailable sources and unsupported ecosystems must be reported as incomplete
or unassessed, never as proof that installed packages are secure.

The terminal output presents an overview, findings, assessment sections, and a
final result. The M9 reporting milestone will continue to refine the default
report into a clearer, action-oriented final review. `--details` expands
available evidence and inventories without changing the security rules.

Use `--format html`, `--format markdown`, or `--format json` to save a report.
The same formats are available for full and targeted scans. Export files are
saved under `~/vulpnix_reports`. Exporting does not change the assessment rules.

### What the checks do

- **`scan`** runs the currently implemented full assessment: host facts,
  service inventory, local accounts and privileges, filesystem metadata and
  bounded SUID/SGID discovery, global SSH configuration, selected
  kernel-hardening parameters, local listening/bound sockets, SSH host-key
  metadata, systemd unit/drop-in metadata, and package inventory with
  vulnerability advisory correlation. Remote package checks may be incomplete
  if an advisory source or network connection is unavailable.

- **`scan host`** reports hostname, distribution, kernel, architecture, and
  uptime. `scan host --details` also includes selected kernel-hardening checks.
- **`scan hardening`** reads a fixed allow-list of kernel `sysctl` parameters in
  read-only mode. Context-dependent values are marked for review rather than
  automatically treated as vulnerabilities.
- **`scan network`** inventories listening TCP and bound UDP sockets, their
  address/port and bind scope, and process attribution where available. It uses
  `ss` when usable and falls back to `/proc/net` when possible. It also inventories
  network interfaces and addresses, collects supported firewall rulesets in
  read-only mode, and performs a preliminary, conservative analysis of supported
  firewall input and forwarding policies. Findings that cannot be assessed
  reliably are reported as `REVIEW`, not as confirmed vulnerabilities. A
  permissive forwarding policy alone does not prove that IP forwarding is enabled,
  that a route exists, or that traffic is reachable from the internet. The
  analyzer does not yet fully resolve interactions between firewall chains, hooks,
  and backends.
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

- **`scan packages`** collects locally installed package metadata using
  the detected native package manager and correlates installed versions with
  supported remote distribution-aware vulnerability advisory sources.
  Inventory and the CVE/advisory audit run together by default. Network access
  is required for remote source queries.
- Package inventory and vulnerability correlation are separate concepts. A
  successful inventory does not establish that installed packages are free
  from vulnerabilities. Unsupported ecosystems, unavailable or stale
  advisories, missing version information, and inconclusive version comparisons
  must remain unassessed or require review rather than being reported as secure.

## Result semantics

- **NO VERIFIED ISSUES** — no verified failing finding and coverage is complete.
- **REVIEW REQUIRED** — one or more checks need review or could not be completed
  reliably.
- **ISSUES DETECTED** — one or more insecure conditions were verified by the
  relevant rule criteria.

`REVIEW`, `NOT_ASSESSED`, and `ERROR` are not confirmed vulnerabilities. A
listening port, active service, non-default setting, or SUID/SGID bit is not by
itself proof of a vulnerability.

Verified `FAIL` findings with documented risk profiles receive a qualitative
score using impact (1–5) multiplied by probability (1–5). These factors express
a documented assessment, not statistical probabilities. Findings without a
complete valid profile remain unscored.

The observed host/scan-scope risk score is the maximum eligible per-finding score,
not a sum. It is always displayed on a 0–25 scale, with 0/25 meaning no eligible
verified `FAIL` finding was scored. Unscored verified failures and incomplete
coverage are shown separately; 0/25 is not proof of safety. Targeted scans score
only their reported scope. Package vulnerability correlation remains an initial,
source-limited implementation, not a complete vulnerability scanner.

## Requirements and data sources

Vulpnix targets Linux and requires Python 3.10 or later. The current development
environment is Arch Linux; compatibility with other distributions still needs
validation on real systems.

The tool assesses the local host. Depending on availability and privileges, it
collects operating-system and kernel facts, local account and privilege metadata,
service state, selected SSH configuration, filesystem permissions and ownership,
network sockets and interfaces, firewall ruleset observations, and selected
kernel-hardening values. It does not require a remote target or a user-provided
baseline.

Collectors use supported local interfaces and commands where available, including
`ss`, `ip`, `systemctl`, `sshd`, `nft`, `iptables-save`, and `ip6tables-save`.
Some checks rely on systemd or other host capabilities. Missing tools, insufficient
permissions, and unsupported capabilities are reported as limitations rather than
evidence that a host is secure. Individual checks may require root.

## References

The implementation draws on the host's local interfaces and documentation for the
relevant Linux utilities and configuration formats:

- Linux account databases: `passwd(5)`, `shadow(5)`, `group(5)`, `gshadow(5)`.
- Kernel parameters and proc interfaces: `sysctl(8)`, `proc(5)`.
- Network interfaces and sockets: `ip(8)`, `ss(8)`.
- SSH server configuration: `sshd_config(5)`.
- systemd services and unit definitions: `systemctl(1)`, `systemd.unit(5)`.
- Firewall inspection: `nft(8)`, `iptables-save(8)`, `ip6tables-save(8)`.
- Arch Linux Security Tracker: [official advisory dataset](https://security.archlinux.org/all.json).
- OSV: [batch query API documentation](https://google.github.io/osv.dev/post-v1-querybatch/).

Consult the manuals installed on the assessed host for the behavior of its
specific utility versions. Vulpnix implements a selected set of checks; it is not
a complete Linux compliance benchmark or firewall-policy verifier.

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

A virtual environment is recommended. From the project root, install the
package with:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Vulpnix requires Python 3.10 or later and declares the runtime dependency
`cvss>=3.6,<4.0`. Its build configuration requires `setuptools>=68`.
Operating-system commands used by individual collectors are separate from
Python package dependencies. Missing tools or unsupported capabilities may
cause checks to be reported as unavailable.

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

See [PLANS.md](PLANS.md). Network socket visibility, interface inventory,
read-only firewall ruleset collection with preliminary policy analysis, selected
kernel hardening, SSH host-key metadata, systemd unit metadata, qualitative
per-finding risk scoring, installed-package inventory, and initial package/CVE
correlation are implemented. Package advisory coverage remains limited and requires further validation. Initial disk/filesystem assessment and qualitative per-finding risk scoring are implemented, but M5–M8 still require the applicable quality checks described in `QUALITY.md`. Comprehensive firewall-policy validation, baseline/change detection, host-wide risk aggregation, and further terminal UX refinement remain planned work. HTML, Markdown, and JSON report exports are implemented; release qualification and cross-distribution validation remain pending.
