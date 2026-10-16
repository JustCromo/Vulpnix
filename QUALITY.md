# Vulpnix Quality Standard

This document defines the minimum quality bar for every Vulpnix milestone. It
applies retroactively to M1–M4 and M4.5, and prospectively to M5 and every
later milestone. It is a development and release gate, not a claim that the
current project has already satisfied every requirement.

## 1. Quality objective

Vulpnix must produce results that are useful, explainable, repeatable, and
appropriately cautious. A feature is not considered reliable just because it
runs or its happy-path tests pass. Its conclusions must be supported by
inspectable evidence, and its limitations must be visible to the user.

**Implementation complete is not the same as quality-qualified.** A milestone
may have all planned code implemented while its qualification review remains
pending.

## 2. Required behavior for security assessments

### Evidence and conclusions

- `PASS` means the relevant condition was checked successfully with sufficient
  and reliable evidence.
- `FAIL` means an insecure condition was positively verified by the rule's
  stated criteria.
- `REVIEW` means evidence exists but context or a human decision is needed; it
  is not, by itself, a confirmed vulnerability.
- `NOT_ASSESSED` means the check could not reach a reliable conclusion.
- `ERROR` means the check failed unexpectedly.
- Missing, malformed, inaccessible, stale, or unsupported data must never be
  silently converted into `PASS` or `FAIL`.
- A finding must explain what was observed, why it matters, and what a sensible
  next step is. Recommendations must not claim more than the evidence supports.
- A fact such as an active service, listening port, or SUID bit is not by itself
  proof of a vulnerability.
- The observed host/scan-scope risk score is the maximum eligible per-finding
  score among verified FAIL findings with complete valid risk profiles; scores are
  not summed. It is 0/25 when no eligible verified FAIL finding is scored. Unscored
  verified failures and incomplete coverage must be disclosed separately: 0/25 is
  not proof of safety, and unknowns must not be converted into reassurance.

### Safety and least privilege

- Assessment commands must not change the system being assessed. Remediation,
  configuration edits, service restarts, package installation, and other
  state-changing actions are out of scope unless explicitly designed as a
  separate, opt-in feature with its own safety review.
- Vulpnix must not elevate privileges itself. It must work rootless where
  possible and report checks that require more privileges without disguising
  missing coverage.
- Use argument-list subprocess calls with `shell=False`; validate arguments
  and handle missing utilities, non-zero exits, timeouts, and malformed output.
- Put explicit bounds on potentially expensive scans, and disclose when those
  bounds make coverage partial.
- Security-sensitive filesystem traversal must define its symlink, mount-point,
  permission, and resource-limit behavior. Do not read sensitive file contents
  when metadata is sufficient for the stated check.
- Treat command output, local files, usernames, paths, service names, and other
  host-controlled values as untrusted input, including when rendering them in
  the terminal or reports.
- Do not send host data to external services by default. Any future network
  lookup or data upload must be explicit, documented, and designed to minimize
  disclosure.

### Portability

- Linux is the target, not one particular distribution. Detect capabilities and
  isolate distribution-specific behavior in adapters or collectors.
- Missing commands, unsupported implementations, and differences between
  distributions must produce clear partial/unavailable results, not crashes or
  guessed conclusions.
- Documentation must distinguish the intended support scope from the systems
  actually tested. Do not claim broad Linux compatibility based only on testing
  on Arch Linux.

## 3. Required tests for each change

Add or update tests alongside the behavior they protect. Depending on the
feature, the test set must cover:

1. **Expected behavior:** representative safe and insecure cases.
2. **Negative cases:** conditions that look suspicious but do not meet the
   rule's criteria, to guard against false positives.
3. **Incomplete evidence:** absent utilities, permission failures, missing or
   malformed fields, and unsupported capabilities.
4. **Adversarial inputs and boundaries:** unexpected values, path and symlink
   cases, duplicate or contradictory records, and resource limits where relevant.
5. **Failure handling:** non-zero exit status, timeout, parser errors, and
   recoverable failures in a full scan.
6. **Regression:** existing behavior in completed milestones remains unchanged
   unless an intentional change is documented and tested.

Prefer deterministic unit tests with fixtures and mocked external commands.
Use integration tests to confirm collectors and parsers work together. Keep
privileged or host-dependent tests explicit and safely isolated; the ordinary
unit-test suite must not alter the developer's machine.

Passing tests are necessary but do not independently prove that a security rule
is correct. For meaningful security checks, also validate known-good and
known-bad scenarios in a controlled Linux VM or equivalent test environment.
Record the expected result and the evidence used to verify the test setup.

## 4. Milestone acceptance gate

Before a milestone can be marked **QUALITY-QUALIFIED**, review all applicable
items below and record the evidence in the roadmap, release notes, or a test
record:

- [ ] **Scope:** supported behavior, exclusions, and assumptions are documented.
- [ ] **Correctness:** each rule has explicit criteria and tests for its relevant
      PASS, FAIL, and uncertain/error paths.
- [ ] **Safety:** privilege use, subprocesses, filesystem access, and resource
      consumption have been reviewed for the feature.
- [ ] **Coverage:** partial or unavailable checks are visible in individual and
      full-scan results; a partial scan cannot be presented as complete.
- [ ] **Portability:** capability differences and unsupported environments are
      handled explicitly; tested environments are recorded.
- [ ] **Regression:** the full automated test suite passes.
- [ ] **Runtime check:** the feature has been exercised through the real CLI,
      not only through isolated function tests.
- [ ] **Output:** findings, explanations, recommendations, and final statuses
      accurately reflect the collected evidence.
- [ ] **Documentation:** usage, privilege requirements, limitations, and new
      behavior are documented.
- [ ] **Review hygiene:** `git diff --check` passes; no secrets, host-specific
      artifacts, temporary files, or generated bytecode are included.

A criterion may be marked not applicable only with a brief reason. Known gaps
must be recorded and explicitly accepted or assigned follow-up work; they must
not be hidden to obtain a qualified status.

## 5. Release gate

Before publishing a release intended for use outside the development machine:

- run the full automated test suite and the project's configured static checks;
- verify the documented per-user and system-wide installation paths and
  the resulting command location in a clean environment; test upgrade and
  uninstall using the same pipx configuration;
- exercise rootless and privileged execution in a disposable Linux VM;
- verify at least one known-good and one known-bad fixture for each high-impact
  security rule;
- test and document a representative set of Linux distributions before making
  multi-distribution support claims;
- inspect terminal and machine-readable outputs for accuracy and sensitive data;
- document known limitations, supported environments, and how to report bugs.

Do not claim that Vulpnix is vulnerability-free or that a scan proves a host is
secure. The tool reports only the checks it can perform and the evidence those
checks support.

## 6. Retroactive qualification of the existing milestones

M1–M4 and M4.5 were marked implementation-complete before this standard
existed. They must be reviewed against the same acceptance gate. M5 development
is in progress; this does not qualify earlier milestones, waive release
criteria, or justify describing the current tool as fully validated. Existing
code is not presumed incorrect; its quality qualification is simply not yet
established.

| Area | Required retrospective review |
|---|---|
| M1 — Foundation | CLI command/error paths, lifecycle and exit behavior, package entry point, predictable output, and basic regression tests. |
| M2 — Host & SSH | Host/service capability detection; SSH option parsing; supported and unsupported OpenSSH behavior; positive, negative, incomplete, and error cases; no daemon changes. |
| M3 — Users & Privileges | Account/group parsing, UID 0 and privilege detection, sudo evidence, incomplete account state, malformed/unavailable data, and rootless behavior. |
| M4 — Filesystem | Sensitive-file metadata only; permission/mode/ownership cases; symlink and mount safety; set-ID criteria; non-ELF and ambiguous cases; traversal limits and partial coverage. |
| M4.5 — Scan architecture & CLI | Consistent scan lifecycle; behavior when one collector fails; full-scan partial coverage; rootless/privileged messaging; narrow terminal output; actual interactive progress; report/finding consistency. |

Current qualification state for all five areas: **PENDING REVIEW**. The
currently passing automated suite is a useful regression signal, but does not
replace this feature-by-feature review or controlled live-system validation.
