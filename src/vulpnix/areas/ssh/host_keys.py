"""SSH host private-key metadata, expressed through the Area contract.

Collection and rules are unchanged (``collectors.ssh_keys``,
``rules.ssh_keys``). Only filesystem metadata is inspected; key contents are
never read.

What changes with the new model is where each outcome goes:

* a checked key (PASS, FAIL or REVIEW) becomes a fact, plus a finding when it
  is not PASS;
* anything that could not be inspected becomes a *gap*, not a finding: not
  being able to look is a coverage limit, not a security observation.
"""

from __future__ import annotations

from collections.abc import Callable

from vulpnix.collectors.ssh_keys import collect_ssh_host_key_metadata
from vulpnix.context import ExecutionContext
from vulpnix.core import AreaResult, AreaStatus, Fact, FindingStatus, Gap
from vulpnix.models import SSHHostKeyObservation
from vulpnix.rules.ssh_keys import assess_ssh_host_key_metadata

NOTES = (
    "Only path, file type, owner and mode are inspected. "
    "Private-key contents are never read.",
    "Only the default /etc/ssh directory is inspected; "
    "keys configured elsewhere with HostKey are not checked.",
)

_NOT_INSPECTED = {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR}


def _describe(observation: SSHHostKeyObservation) -> str:
    """State what was observed about one key file, without judging it."""
    if observation.is_symlink:
        return "symbolic link; target not inspected"
    if observation.is_regular is not True:
        return "not a regular file"
    owner = "root-owned" if observation.owner_uid == 0 else f"owner UID {observation.owner_uid}"
    return f"{owner} regular file, mode {observation.mode:04o}"


class SSHHostKeyArea:
    """Ownership and permissions of the OpenSSH host private-key files."""

    id = "ssh_host_keys"
    title = "SSH HOST-KEY METADATA"
    description = "SSH host-key file ownership and permissions"

    def __init__(
        self,
        collector: Callable[[], tuple[SSHHostKeyObservation, ...]] | None = None,
    ) -> None:
        # ``None`` resolves the collector at run time so tests can patch it.
        self._collector = collector

    def run(self, ctx: ExecutionContext) -> AreaResult:
        collector = self._collector or collect_ssh_host_key_metadata
        observations = collector()
        if not observations:
            return AreaResult(
                area_id=self.id,
                title=self.title,
                status=AreaStatus.NOT_ASSESSED,
                gaps=(Gap("no-observations", "No SSH host-key observations were collected."),),
            )

        assessment = assess_ssh_host_key_metadata(observations)
        facts: list[Fact] = []
        gaps: list[Gap] = []
        # The rules return exactly one check per observation, in order.
        for observation, check in zip(observations, assessment.checks, strict=True):
            if check.status in _NOT_INSPECTED:
                gaps.append(Gap(f"host_key_not_inspected:{observation.path}", check.evidence))
            else:
                facts.append(
                    Fact(
                        f"host_key:{observation.path}",
                        observation.path,
                        _describe(observation),
                        check.status,
                    )
                )

        findings = tuple(
            finding for finding in assessment.findings
            if finding.status not in _NOT_INSPECTED
        )
        if gaps and not facts:
            status = AreaStatus.NOT_ASSESSED
        elif gaps:
            status = AreaStatus.PARTIAL
        else:
            status = AreaStatus.COMPLETE
        return AreaResult(
            area_id=self.id,
            title=self.title,
            status=status,
            findings=() if status is AreaStatus.NOT_ASSESSED else findings,
            facts=tuple(facts),
            gaps=tuple(gaps),
            notes=NOTES,
        )
