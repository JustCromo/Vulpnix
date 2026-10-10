# Vulpnix

Vulpnix is a Linux host risk assessment tool. It is intended to help assess
host configuration and surface potential risks.

The project is at an early stage. Its interactive CLI collects host, user,
service, SSH, and selected sensitive-file metadata, then presents verified
security conditions and information that could not be assessed.

## Current SSH checks

When OpenSSH is available and supports `sshd -G`, Vulpnix reviews the global
effective values for root login, password authentication, empty passwords, and
public-key authentication. Findings are review prompts, not a complete risk
score.

Use `scan` for the full Linux assessment, including host facts, users, services,
SSH, and sensitive-file metadata. Use `scan host` for host details,
`scan service` for services and startup state, `scan ssh` for the SSH assessment,
or `scan filesystem` to inspect metadata for `/etc/passwd`, `/etc/shadow`,
`/etc/group`, and `/etc/gshadow`, plus bounded SUID/SGID discovery under
`/usr`, `/opt`, `/bin`, and `/sbin`. Nested mounts are skipped; discovery stops
after 250,000 entries or 10 seconds and reports partial coverage. Set-ID bits
alone are not findings: Vulpnix reports a FAIL only for a verified executable
ELF with active set-ID permissions and world-write access on a mount where
execution is allowed. This check does not execute binaries or escalate
privileges. The SSH commands use the normal
global effective configuration and require no connection context arguments.

SSH `Match` rules can change settings for a particular user or connection, so
these global results are not an effective access check for a specific client.
The collector can accept a connection context internally for future use. If
Vulpnix cannot reliably collect the SSH configuration, it reports it as
unavailable / not assessed and does not generate SSH findings.
