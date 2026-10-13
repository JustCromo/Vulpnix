"""Interactive command shell for Vulpnix."""

from collections.abc import Callable
from contextlib import redirect_stdout
from dataclasses import dataclass, replace
import io
import subprocess
import sys

try:
    import readline
except ImportError:
    readline = None

from vulpnix.collectors import (
    collect_local_users,
    collect_sensitive_file_metadata,
    collect_setid_files,
    collect_services,
    collect_ssh_config,
    collect_sudo_privileges,
    collect_system_info,
    collect_sysctl_observations,
    collect_network_snapshot,
    collect_ssh_host_key_metadata,
    collect_service_unit_file_metadata,
)
from vulpnix.collectors.ssh import SSHCommandError, SSHGUnsupportedError
from vulpnix.models import (
    FileMetadata,
    FileMetadataResult,
    FileMetadataStatus,
    SSHConfig,
    Service,
    SudoPrivilege,
    SudoPrivilegeStatus,
    SystemInfo,
    User,
    HardeningAssessment,
    NetworkSnapshot,
    SSHHostKeyAssessment,
    UnitFileAssessment,
)
from vulpnix import __version__
from vulpnix.findings import Finding, FindingStatus
from vulpnix.cli.terminal import (
    copy_text_to_clipboard,
    extract_selected_text,
    MouseTextSelection,
    _parse_sgr_mouse_event,
    highlight_columns,
    accent,
    alternate_screen,
    clip_ansi_line,
    clear_screen,
    display_width,
    raw_input_mode,
    read_key,
    terminal_size,
    wrap_text,
)
from vulpnix.cli.report import (
    ReportBlock,
    ReportSection,
    ScanReport,
    render_report_section,
    render_scan_report,
)
from vulpnix.rules.filesystem import (
    FilesystemAssessment,
    assess_sensitive_files,
    assess_setid_files,
)
from vulpnix.rules import (
    check_ssh_empty_passwords,
    check_ssh_password_authentication,
    check_ssh_public_key_authentication,
    check_ssh_root_login,
    verified_privileged_accounts,
)

from vulpnix.scan.orchestrator import ScanOrchestrator
from vulpnix.scan.privilege import current_privilege_context
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.rules.hardening import assess_kernel_hardening
from vulpnix.scan.progress import ScanProgress, ScanStage


_FOX_ART = (
    "                  .................###%%#:.",
    "                ..................=%%#***---=",
    "              ....................-++=========",
    "            .......:------::::::::-=============",
    "          .........::..............=============",
    "         .......................:--------=======",
    "         .....................-----===---====-====",
    "         .....--+*###%*---------=-.........::------=",
    "         ......:=#####+====-----...........::::-----=",
    "         ........+%%*-=====---:............::::::-----",
    "         ........:*#=-=====--:..............::::::--===",
    "         ..........--=======-..............:::::::--===",
    "         .....---::--=======-.............:+-:::::--===",
    "         .............======-...........*%##*-::::--===",
    "         ..............:-==---......:::-####+::::---==",
    "         .................-----:::::::::::::::::---===",
    "         ..........::::::::-----::::::::::::::::-====",
    "         .....-----------:::------::::::::::---===++",
    "         .....................:-==-----::---===+++==",
    "         ........................:-===========++==----",
    "         ...................................   ===-----",
    "         .....-------:::::..................     ==-----",
    "         ...................................      ===---+#",
    "         ...................................       ==++*###",
    "          ..................................        +#%%###",
    "           :..............................            %%%",
)
_PRESENTATION_INDENT = "    "
_TITLE_BOX_WIDTH = 34
_OUTPUT_LAYOUT_CACHE: tuple[int, int, int, str, list[str]] | None = None
_SECTION_WIDTH = 48
_LIVE_PROGRESS = False


@dataclass(frozen=True)
class Command:
    """One supported Vulpnix command and its help metadata."""

    name: str
    group: str
    description: str
    handler: Callable[[], None] | None


def _show_help() -> None:
    """Print the commands currently supported by the shell."""
    print(f"\n{accent('COMMANDS')}")
    group_names = dict.fromkeys(command.group for command in _COMMANDS)
    for group_name in group_names:
        print(f"\n{group_name}")
        for command in _COMMANDS:
            if command.group == group_name:
                print(f"  {command.name:<8} {command.description}")
                if command.name == "scan":
                    print("  scan --details  Full assessment with expanded check details")
                    print("  scan host  Host facts only")
                    print("  scan host --details  Host facts and kernel hardening checks")
                    print("  scan hardening [--details]  Read-only kernel hardening checks")
                    print("  scan users  User and privilege assessment")
                    print("  scan users --details  Include the complete account inventory")
                    print("  scan service  Services and startup state")
                    print("  scan service --details  Include unit-file ownership and permissions")
                    print("  scan ssh  SSH assessment only")
                    print("  scan ssh --details  Show all SSH and host-key metadata checks")
                    print("  scan filesystem  Sensitive file metadata and set-ID checks")
                    print("  scan filesystem --details  Include expanded findings")
                    print("  scan network [--details]  Listening sockets and bind scope")
                    print("  Run once with: sudo vulpnix — all commands in the shell inherit UID 0")


def _show_version() -> None:
    """Print the installed Vulpnix package version."""
    print(f"Vulpnix {__version__}")


def _show_info() -> None:
    """Show the project's purpose and current implementation status."""
    print(f"\n{accent('VULPNIX')}")
    print("Linux host risk assessment")
    print("\nA project to inspect Linux hosts and explain security findings.")
    print(f"\n{accent('DESIGN GOAL')}")
    print("Evidence-backed results · clear explanations · fewer false positives")
    print(f"\n{accent('CURRENT STATUS')}")
    print("Shared scan orchestration with rootless and privileged execution modes.")


def _clear_screen() -> None:
    """Refresh the screen and restore the initial presentation."""
    clear_screen()
    _show_presentation()


def _display_value(value: str | None) -> str:
    """Keep locally collected text on one safe, readable terminal line."""
    if not value:
        return "Unavailable"
    safe_value = "".join(character if character.isprintable() else "�" for character in value)
    if len(safe_value) > 80:
        return safe_value[:77] + "…"
    return safe_value


def _section(title: str) -> None:
    """Print a consistent, compact section heading."""
    rule_width = min(max(terminal_size()[0], 1), _SECTION_WIDTH)
    print(f"\n{accent(title, bold=True)}")
    print(f"{'─' * rule_width}")


def _format_uptime(seconds: float | None) -> str:
    if seconds is None:
        return "Unavailable"
    minutes = int(seconds // 60)
    days, remaining_minutes = divmod(minutes, 24 * 60)
    hours, remaining_minutes = divmod(remaining_minutes, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if remaining_minutes or not parts:
        parts.append(f"{remaining_minutes}m")
    return " ".join(parts)


def _render_result(result, *, details: bool = True) -> None:
    """Render a normalized scan result with the shared terminal renderer."""
    report = ScanReport(
        host=result.host,
        sections=result.sections,
        findings=result.findings,
        scope=result.scope,
        coverage=result.coverage,
        review_items=result.review_items,
        privilege=result.privilege,
        details=details,
    )
    print("\n".join(render_scan_report(report, terminal_size()[0])))


def _progress_callback(event: ScanProgress) -> None:
    if not _LIVE_PROGRESS:
        return
    stream = sys.__stdout__
    stream.write(f"\r\033[K  {event.stage.value:<10} {event.message}")
    stream.flush()
    if event.stage in {ScanStage.COMPLETED, ScanStage.ERROR}:
        stream.write("\n")
        stream.flush()


def _make_orchestrator() -> ScanOrchestrator:
    return ScanOrchestrator(progress_callback=_progress_callback if _LIVE_PROGRESS else None)


def _combine_results(base, *extras):
    """Combine independent read-only checks into one truthful overall report."""
    sections = list(base.sections)
    findings = list(base.findings)
    scope = list(base.scope)
    review_items = base.review_items
    partial = base.coverage is AssessmentCoverage.PARTIAL
    for extra in extras:
        sections.extend(extra.sections)
        findings.extend(extra.findings)
        for item in extra.scope:
            if item not in scope:
                scope.append(item)
        review_items += extra.review_items
        partial = partial or extra.coverage is AssessmentCoverage.PARTIAL
    return replace(
        base,
        sections=tuple(sections),
        findings=tuple(findings),
        scope=tuple(scope),
        coverage=AssessmentCoverage.PARTIAL if partial else AssessmentCoverage.COMPLETE,
        review_items=review_items,
    )


def _hardening_report_section(assessment: HardeningAssessment, *, details: bool = False) -> ReportSection:
    checks = assessment.checks
    passed = sum(check.status is FindingStatus.PASS for check in checks)
    failed = sum(check.status is FindingStatus.FAIL for check in checks)
    review = sum(check.status is FindingStatus.REVIEW for check in checks)
    unavailable = sum(check.status in {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR} for check in checks)
    unresolved = tuple(check for check in checks if check.status is not FindingStatus.PASS)
    lines = tuple(
        f"[{check.status.value}] {check.key}: "
        f"observed={check.observed if check.observed is not None else 'unavailable'}; "
        f"expected={check.expected}"
        + (f" ({check.reason})" if check.reason else "")
        for check in (checks if details else unresolved[:8])
    )
    items = tuple(
        f"[{check.status.value}] {check.title}: "
        f"{check.observed if check.observed is not None else 'unavailable'}"
        for check in unresolved[:6]
    )
    if not items:
        items = ("All available hardening parameters matched the defined checks.",)
    elif len(unresolved) > len(items):
        remaining = len(unresolved) - len(items)
        if details:
            message = f"{remaining} additional check(s) are included in CHECK DETAILS."
        else:
            message = f"{remaining} additional check(s) omitted; use --details to list them."
        items += (message,)
    blocks = (ReportBlock("CHECK DETAILS", lines=lines),) if details else ()
    return ReportSection(
        title="KERNEL HARDENING",
        facts=(
            ("Parameters checked", str(len(checks))),
            ("Expected values", str(passed)),
            ("Verified concerns", str(failed)),
            ("Context review", str(review)),
            ("Unavailable/error", str(unavailable)),
        ),
        items=items,
        items_label="Items requiring attention:" if unresolved else "Assessment:",
        footer="Read-only sysctl checks. Role-dependent settings are marked REVIEW, not automatically treated as vulnerabilities.",
        blocks=blocks,
    )


def _network_endpoint_text(endpoint) -> str:
    address = f"[{endpoint.address}]" if ":" in endpoint.address and not endpoint.address.startswith("[") else endpoint.address
    port = "?" if endpoint.port is None else str(endpoint.port)
    process = endpoint.process_name or "owner unavailable"
    if endpoint.pid is not None:
        process += f" (PID {endpoint.pid})"
    return f"{endpoint.protocol.upper()} {address}:{port} · {endpoint.state} · {endpoint.bind_scope} · {process}"


def _network_report_section(snapshot: NetworkSnapshot, *, details: bool = False) -> ReportSection:
    endpoints = snapshot.endpoints
    tcp_count = sum(item.protocol.startswith("tcp") for item in endpoints)
    udp_count = sum(item.protocol.startswith("udp") for item in endpoints)
    loopback = sum(item.bind_scope == "LOOPBACK" for item in endpoints)
    all_interfaces = sum(item.bind_scope == "ALL INTERFACES" for item in endpoints)
    non_loopback = sum(item.bind_scope == "NON-LOOPBACK" for item in endpoints)
    limit = 60 if details else 8
    items = tuple(_network_endpoint_text(item) for item in endpoints[:limit])
    if not items:
        items = ("No listening TCP or bound UDP sockets were reported.",)
    elif len(endpoints) > limit:
        items += (f"{len(endpoints) - limit} additional socket(s) omitted; use --details to list more.",)
    review = list(snapshot.review)
    if endpoints and not snapshot.process_attribution_complete and not any("process ownership" in item for item in review):
        review.append("process ownership could not be confirmed for the full socket inventory")
    if review:
        items += tuple(f"REVIEW: {item}" for item in review[:3])
    return ReportSection(
        title="NETWORK EXPOSURE",
        facts=(
            ("Inventory source", snapshot.source),
            ("Sockets", str(len(endpoints))),
            ("TCP listeners", str(tcp_count)),
            ("UDP bound sockets", str(udp_count)),
            ("Loopback-bound", str(loopback)),
            ("All interfaces", str(all_interfaces)),
            ("Other non-loopback", str(non_loopback)),
            ("Process attribution", "complete" if snapshot.process_attribution_complete else "limited / not verified"),
        ),
        items=items,
        items_label="Local socket inventory (bind scope is not proof of internet reachability):",
        footer="An open/listening port is an observation, not automatically a vulnerability.",
    )


def _ssh_host_key_report_section(assessment: SSHHostKeyAssessment, *, details: bool = False) -> ReportSection:
    checks = assessment.checks
    passed = sum(item.status is FindingStatus.PASS for item in checks)
    failed = sum(item.status is FindingStatus.FAIL for item in checks)
    review = sum(item.status is FindingStatus.REVIEW for item in checks)
    unavailable = sum(item.status in {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR} for item in checks)
    attention = tuple(item for item in checks if item.status is not FindingStatus.PASS)
    if details:
        shown = checks
    else:
        shown = attention[:6]
    items = tuple(f"[{item.status.value}] {item.evidence}" for item in shown)
    if not items:
        items = ("Host-key metadata checks passed; key contents were not read.",)
    if not details and len(attention) > len(shown):
        items += (f"{len(attention) - len(shown)} additional item(s) omitted; use --details to list them.",)
    return ReportSection(
        title="SSH HOST-KEY METADATA",
        facts=(("Keys/observations", str(len(checks))), ("Metadata checks passed", str(passed)), ("Verified issues", str(failed)), ("Review", str(review)), ("Unavailable/error", str(unavailable))),
        items=items,
        items_label="Host-key metadata:",
        footer="Only path, file type, owner and mode are inspected. Private-key contents are never read.",
    )


def _unit_file_report_section(assessment: UnitFileAssessment, *, details: bool = False) -> ReportSection:
    checks = assessment.checks
    passed = sum(item.status is FindingStatus.PASS for item in checks)
    failed = sum(item.status is FindingStatus.FAIL for item in checks)
    review = sum(item.status is FindingStatus.REVIEW for item in checks)
    review += len(assessment.review)
    unavailable = sum(item.status in {FindingStatus.NOT_ASSESSED, FindingStatus.ERROR} for item in checks)
    attention = tuple(item for item in checks if item.status is not FindingStatus.PASS)
    shown = checks if details else attention[:8]
    items = tuple(f"[{item.status.value}] {item.unit}: {item.evidence}" for item in shown)
    if not items:
        items = ("No unit-file metadata issues were identified in the collected scope." if checks else "No systemd unit-file metadata was available to inspect.",)
    if assessment.review:
        review_items = assessment.review if details else assessment.review[:3]
        items += tuple(f"REVIEW: {item}" for item in review_items)
        if not details and len(assessment.review) > len(review_items):
            omitted = len(assessment.review) - len(review_items)
            items += (
                f"{omitted} additional coverage review item(s) omitted; "
                "use --details to list them.",
            )
    if not details and len(attention) > len(shown):
        items += (f"{len(attention) - len(shown)} additional item(s) omitted; use --details to list them.",)
    return ReportSection(
        title="SYSTEMD UNIT FILES",
        facts=(("Files inspected", str(len(checks))), ("Metadata passed", str(passed)), ("Verified issues", str(failed)), ("Review", str(review)), ("Unavailable/error", str(unavailable))),
        items=items,
        items_label="Unit fragment/drop-in metadata:",
        footer="File contents are not read. Writable or non-root-owned service definitions can affect privileged service execution.",
    )


def _run_hardening_result(*, details: bool = False):
    try:
        return _make_orchestrator().run_hardening(
            collector=collect_sysctl_observations,
            section_builder=lambda assessment: _hardening_report_section(assessment, details=details),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        return _make_orchestrator()._result(
            sections=(ReportSection("KERNEL HARDENING", status="NOT_ASSESSED", message=f"Kernel hardening data is unavailable: {_display_value(str(error))}"),),
            scope=("kernel hardening",), coverage=AssessmentCoverage.PARTIAL, review_items=1,
        )


def _run_network_result(*, details: bool = False):
    try:
        return _make_orchestrator().run_network(
            collector=collect_network_snapshot,
            section_builder=lambda snapshot: _network_report_section(snapshot, details=details),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        return _make_orchestrator()._result(
            sections=(ReportSection("NETWORK EXPOSURE", status="NOT_ASSESSED", message=f"Socket inventory is unavailable: {_display_value(str(error))}"),),
            scope=("listening sockets",), coverage=AssessmentCoverage.PARTIAL, review_items=1,
        )


def _run_ssh_host_key_result(*, details: bool = False):
    try:
        return _make_orchestrator().run_ssh_host_keys(
            collector=collect_ssh_host_key_metadata,
            section_builder=lambda assessment: _ssh_host_key_report_section(assessment, details=details),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        return _make_orchestrator()._result(
            sections=(ReportSection("SSH HOST-KEY METADATA", status="NOT_ASSESSED", message=f"Host-key metadata is unavailable: {_display_value(str(error))}"),),
            scope=("SSH host-key metadata",), coverage=AssessmentCoverage.PARTIAL, review_items=1,
        )


def _run_unit_file_result(services: tuple[Service, ...], *, details: bool = False):
    try:
        return _make_orchestrator().run_service_unit_security(
            services=services,
            collector=collect_service_unit_file_metadata,
            section_builder=lambda assessment: _unit_file_report_section(assessment, details=details),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        return _make_orchestrator()._result(
            sections=(ReportSection("SYSTEMD UNIT FILES", status="NOT_ASSESSED", message=f"Unit-file metadata is unavailable: {_service_error_message(error)}"),),
            scope=("systemd unit-file metadata",), coverage=AssessmentCoverage.PARTIAL, review_items=1,
        )


def _show_host_assessment(title: str = "SYSTEM", *, details: bool = False) -> bool:
    try:
        result = _make_orchestrator().run_host(
            collector=collect_system_info,
            section_builder=lambda info: ReportSection(
                title=title,
                facts=(
                    ("Hostname", _display_value(info.hostname)),
                    ("Distribution", _display_value(info.distribution) + (f" ({_display_value(info.distribution_version)})" if info.distribution_version else "")),
                    ("Kernel", _display_value(info.kernel_release)),
                    ("Architecture", _display_value(info.architecture)),
                    ("Uptime", _format_uptime(info.uptime_seconds)),
                ),
            ),
        )
    except NotImplementedError:
        result = _make_orchestrator()._result(
            sections=(ReportSection(title=title, status="NOT_ASSESSED", message="Host facts are supported on Linux only."),),
            scope=("system facts",), review_items=1,
        )
        _render_result(result)
        return False
    except (OSError, UnicodeError, ValueError) as error:
        result = _make_orchestrator()._result(
            sections=(ReportSection(title=title, status="NOT_ASSESSED", message=_display_value(str(error))),),
            scope=("system facts",), review_items=1,
        )
        _render_result(result)
        return False
    if details:
        result = _combine_results(result, _run_hardening_result(details=True))
    _render_result(result, details=details)
    return True


def _service_error_message(error: Exception) -> str:
    if isinstance(error, FileNotFoundError):
        return "systemctl is not installed."
    if isinstance(error, subprocess.TimeoutExpired):
        return "systemctl did not respond in time."
    if isinstance(error, subprocess.CalledProcessError):
        return "systemd could not be queried; access may be restricted."
    if isinstance(error, (UnicodeError, ValueError)):
        return "systemd returned unreadable service data."
    return "systemd service data is unavailable."


def _user_report_section(
    users: tuple[User, ...],
    sudo_privileges: tuple[SudoPrivilege, ...] = (),
    *,
    detailed: bool = False,
) -> ReportSection:
    uid_zero = sum(user.uid == 0 for user in users)
    sudo_by_account = {result.account: result for result in sudo_privileges}
    privileged_users = verified_privileged_accounts(users, sudo_privileges)
    known_privileged = len(privileged_users)
    group_unavailable = sum(user.groups is None for user in users)
    account_state_unavailable = sum(user.account_state is None for user in users)
    uid_zero_users = tuple(user for user in users if user.uid == 0)
    additional_uid_zero = tuple(
        user for user in uid_zero_users if user.username != "root"
    )
    sudo_accounts = tuple(
        result.account
        for result in sudo_privileges
        if result.status is SudoPrivilegeStatus.PRIVILEGES_FOUND and result.grants
    )
    assessment: list[str] = []
    if not uid_zero_users:
        assessment.append("No UID 0 accounts detected")
    elif not additional_uid_zero:
        assessment.append("✓ Only one UID 0 account detected: root")
    else:
        assessment.append(
            "Additional UID 0 accounts detected: "
            + ", ".join(user.username for user in additional_uid_zero)
        )
    if known_privileged:
        assessment.append(
            f"✓ Privileged access verified for {known_privileged} "
            f"{'account' if known_privileged == 1 else 'accounts'}"
        )
    else:
        assessment.append("No privileged accounts verified")
    if sudo_accounts:
        assessment.append(
            f"✓ Sudo access verified for {len(sudo_accounts)} "
            f"{'account' if len(sudo_accounts) == 1 else 'accounts'}"
        )
    else:
        no_sudo_accounts = sum(
            result.status is SudoPrivilegeStatus.NO_PRIVILEGES
            for result in sudo_privileges
        )
        if no_sudo_accounts:
            assessment.append(
                f"No sudo access verified for {no_sudo_accounts} "
                f"inspected {'account' if no_sudo_accounts == 1 else 'accounts'}"
            )

    review: list[str] = []
    if additional_uid_zero:
        review.append(
            "Review authorization for additional UID 0 accounts: "
            + ", ".join(user.username for user in additional_uid_zero)
        )
    sudo_unavailable = sum(
        result.status is SudoPrivilegeStatus.UNAVAILABLE
        for result in sudo_privileges
    )
    sudo_unevaluated = sum(
        result.status is SudoPrivilegeStatus.NOT_ASSESSED
        for result in sudo_privileges
    )
    if sudo_unavailable:
        review.append("sudo is unavailable; sudo privileges could not be evaluated")
    if sudo_unevaluated:
        reason_messages = {
            "non-interactive listing requires authentication":
                "sudo listing requires authentication",
            "permission denied while inspecting another account":
                "permission denied while inspecting another account",
            "other-account inspection skipped because current process permissions are insufficient":
                "other-account inspection skipped; current process lacks permission",
            "sudo output did not contain a recognized account listing":
                "sudo output format was not recognized",
            "sudo privilege listing timed out": "sudo listing timed out",
            "sudo execution blocked by environment or runtime configuration":
                "environment or sudo runtime configuration blocked inspection",
            "sudo output could not be safely parsed":
                "sudo output was malformed or unsupported",
        }
        reasons: dict[str, int] = {}
        for result in sudo_privileges:
            if result.status is SudoPrivilegeStatus.NOT_ASSESSED:
                message = reason_messages.get(
                    result.reason,
                    "sudo privilege state could not be established",
                )
                reasons[message] = reasons.get(message, 0) + 1
        for message, count in reasons.items():
            review.append(
                f"{count} {'account' if count == 1 else 'accounts'}: {message}"
            )
    if account_state_unavailable:
        review.append(
            f"{account_state_unavailable} "
            f"{'account could' if account_state_unavailable == 1 else 'accounts could'} "
            "not be evaluated for account state"
        )
    if group_unavailable:
        review.append(
            f"Group membership unavailable for {group_unavailable} "
            f"{'account' if group_unavailable == 1 else 'accounts'}"
        )
    if not review:
        review.append("No unresolved account information")

    inventory = tuple(
        " · ".join(
            (
                user.username,
                f"UID {user.uid}",
                f"GID {user.gid}",
                "groups: " + (", ".join(user.groups) if user.groups is not None else "Unavailable"),
                "shell: " + (user.shell or "Unavailable"),
                "privileged: " + ("yes" if user.privileged is True else "NOT_ASSESSED"),
                "account state: " + (user.account_state or "NOT_ASSESSED"),
                _sudo_detail(sudo_by_account.get(user.username)),
            )
        )
        for user in users
    )
    details = ReportBlock(
        title="DETAILS",
        lists=(
            ("UID 0", tuple(user.username for user in uid_zero_users)),
            ("Privileged", privileged_users),
            ("Sudo access", sudo_accounts),
        ),
    )
    if detailed:
        details = ReportBlock(
            title="ACCOUNT INVENTORY",
            lines=inventory or ("No local accounts found.",),
        )
    return ReportSection(
        title="USERS",
        facts=(
            ("Local accounts", str(len(users))),
            ("UID 0 accounts", str(uid_zero)),
            ("Privileged accounts", str(known_privileged)),
        ),
        blocks=(
            ReportBlock("ASSESSMENT", lines=tuple(assessment)),
            ReportBlock("REVIEW", lines=tuple(review)),
            details,
        ),
    )


def _sudo_detail(result: SudoPrivilege | None) -> str:
    if result is None:
        return "sudo: NOT_ASSESSED"
    if result.grants:
        grant_details = tuple(
            f"runas={','.join(grant.target_users)}"
            + (
                f":{','.join(grant.target_groups)}"
                if grant.target_groups is not None
                else ""
            )
            + " "
            f"commands={','.join(grant.allowed_commands)}"
            + (f" options={','.join(grant.options)}" if grant.options else "")
            + (f" source={grant.source}" if grant.source else "")
            for grant in result.grants
        )
        context = f" host={result.host}" if result.host else ""
        return "sudo:" + context + " " + "; ".join(grant_details)
    detail = result.status.value
    if result.reason:
        detail += f" ({result.reason})"
    return f"sudo: {detail}"


def _user_error_message(error: Exception) -> str:
    if isinstance(error, FileNotFoundError):
        return "The local passwd database could not be found."
    if isinstance(error, PermissionError):
        return "The local passwd database could not be read."
    if isinstance(error, UnicodeError):
        return "The local account database contains unreadable text."
    if isinstance(error, ValueError):
        return f"The local account database is malformed: {_display_value(str(error))}"
    return "Local account data is unavailable."


def _show_service_assessment(*, detailed: bool = False) -> None:
    collected: list[tuple[Service, ...]] = []

    def build_section(services: tuple[Service, ...]) -> ReportSection:
        collected.append(services)
        return _service_report_section(services, detailed=detailed)

    try:
        result = _make_orchestrator().run_services(collector=collect_services, section_builder=build_section)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        result = _make_orchestrator()._result(
            sections=(ReportSection("SERVICES", status="NOT_ASSESSED", message=_service_error_message(error)),),
            scope=("services",), coverage=AssessmentCoverage.PARTIAL, review_items=1,
        )
    if detailed and collected:
        result = _combine_results(result, _run_unit_file_result(collected[0], details=True))
    _render_result(result, details=detailed)


def _show_users_assessment(*, detailed: bool = False) -> None:
    def build_section(users: tuple[User, ...], sudo_privileges: tuple[SudoPrivilege, ...]) -> ReportSection:
        return _user_report_section(users, sudo_privileges, detailed=detailed)
    try:
        result = _make_orchestrator().run_users(section_builder=build_section, users_collector=collect_local_users, sudo_collector=collect_sudo_privileges)
    except (OSError, UnicodeError, ValueError) as error:
        result = _make_orchestrator()._result(
            sections=(ReportSection("USERS", status="NOT_ASSESSED", message=_user_error_message(error)),),
            scope=("users", "privileges"), review_items=1,
        )
    _render_result(result, details=detailed)


def _file_metadata_summary(metadata: FileMetadata) -> str:
    uid = str(metadata.uid) if metadata.uid is not None else "unavailable"
    gid = str(metadata.gid) if metadata.gid is not None else "unavailable"
    return (
        f"{metadata.path} · {metadata.type} · UID {uid} · "
        f"GID {gid} · mode {metadata.mode:04o} · {metadata.size} bytes"
    )


def _filesystem_report_section(
    results: tuple[FileMetadataResult, ...],
    assessment: FilesystemAssessment,
    setid_coverage,
    setid_assessment,
    *,
    detailed_findings: bool = False,
) -> ReportSection:
    filesystem_findings = tuple(assessment.findings)
    setid_findings = tuple(setid_assessment.findings)
    all_findings = filesystem_findings + setid_findings
    finding_paths = {
        finding.evidence.split(";", 1)[0].removeprefix("Path: ")
        for finding in all_findings
    }
    attention_paths = finding_paths | {item.path for item in assessment.review}
    details: list[str] = []
    metadata_by_path = {
        result.path: result.metadata
        for result in results
        if result.metadata is not None
    }
    for path in sorted(attention_paths):
        metadata = metadata_by_path.get(path)
        if metadata is not None:
            details.append(_file_metadata_summary(metadata))
        else:
            result = next((item for item in results if item.path == path), None)
            reason = result.reason if result else "metadata unavailable"
            details.append(f"{path} · NOT_ASSESSED · {reason}")

    ownership_assessable = sum(
        metadata.uid is not None and metadata.gid is not None
        for metadata in assessment.checked
    )
    assessment_lines = (
        (f"Permission checks completed for {len(assessment.checked)} regular file(s).",)
        if assessment.checked
        else ("No regular files could be assessed.",)
    )
    if ownership_assessable:
        assessment_lines += (
            f"Ownership verified for {ownership_assessable} file(s).",
        )
    if all_findings:
        assessment_lines += tuple(
            f"{finding.status.value} · {finding.title} ({finding.rule_id})"
            for finding in all_findings
        )
    elif assessment.checked:
        assessment_lines += (
            "No defined insecure condition detected among checks with reliable data.",
        )

    review_lines = tuple(
        f"{item.path}: {item.reason}"
        for item in assessment.review
    )
    review_lines += tuple(f"Set-ID: {item}" for item in setid_assessment.review)
    if not review_lines:
        review_lines = ("All defined filesystem checks completed without unresolved review items.",)

    collected = sum(
        result.status in {FileMetadataStatus.COLLECTED, FileMetadataStatus.PARTIAL}
        and result.metadata is not None
        for result in results
    )
    fact_lines = tuple(
        f"{label}: {value}"
        for label, value in (
            ("Target files", str(len(results))),
            ("Metadata collected", f"{collected}/{len(results)}"),
            ("Regular files inspected", str(len(assessment.checked))),
            ("Ownership assessable", f"{ownership_assessable}/{len(assessment.checked)}"),
            ("Verified findings", str(len(all_findings))),
            ("Set-ID regular files", str(len(setid_coverage.files))),
            ("Set-ID review items", str(len(setid_assessment.review))),
            ("Set-ID verified findings", str(len(setid_findings))),
        )
    )
    blocks = [
        ReportBlock("FACTS", lines=fact_lines),
        ReportBlock("ASSESSMENT", lines=assessment_lines),
        ReportBlock("REVIEW", lines=review_lines),
        ReportBlock("DETAILS", lines=tuple(details) or ("No files require additional detail.",)),
    ]
    if detailed_findings and all_findings:
        finding_lines: list[str] = []
        for finding in all_findings:
            finding_lines.extend(
                (
                    f"[{finding.status.value}] {finding.title}",
                    f"Rule: {finding.rule_id}",
                    f"Evidence: {finding.evidence}",
                    f"Why it matters: {finding.explanation}",
                    f"Recommendation: {finding.recommendation}",
                )
            )
        blocks.append(ReportBlock("FINDINGS", lines=tuple(finding_lines)))

    return ReportSection(
        title="FILESYSTEM",
        blocks=tuple(blocks),
    )


def _show_filesystem_assessment(*, detailed: bool = False) -> None:
    def build_section(results, assessment, setid_coverage, setid_assessment):
        return _filesystem_report_section(results, assessment, setid_coverage, setid_assessment, detailed_findings=detailed)
    try:
        result = _make_orchestrator().run_filesystem(section_builder=build_section, sensitive_file_collector=collect_sensitive_file_metadata, sensitive_file_assessor=assess_sensitive_files, setid_collector=collect_setid_files, setid_assessor=assess_setid_files)
    except (OSError, UnicodeError, ValueError) as error:
        result = _make_orchestrator()._result(
            sections=(ReportSection("FILESYSTEM", status="NOT_ASSESSED", message=f"Filesystem checks could not be fully assessed: {_display_value(str(error))}"),),
            scope=("filesystem metadata", "set-ID files"), review_items=1,
        )
    _render_result(result, details=detailed)


def _ssh_error_message(error: Exception) -> str:
    if isinstance(error, FileNotFoundError):
        return "OpenSSH server (sshd) is not installed."
    if isinstance(error, subprocess.TimeoutExpired):
        return "sshd did not return configuration in time."
    if isinstance(error, SSHGUnsupportedError):
        detail = _ssh_command_detail(error)
        return (
            "sshd -G is not supported by this OpenSSH installation."
            f"{detail}"
        )
    if isinstance(error, SSHCommandError):
        return f"sshd -G failed{_ssh_command_detail(error)}."
    if isinstance(error, subprocess.CalledProcessError):
        return "sshd -G could not print the effective configuration."
    if isinstance(error, (UnicodeError, ValueError)):
        return "sshd returned unreadable configuration data."
    return "SSH configuration is unavailable."


def _ssh_command_detail(error: SSHCommandError) -> str:
    if not error.diagnostic:
        return f" (exit {error.returncode})"
    detail = "".join(
        character if character.isprintable() else "�"
        for character in error.diagnostic
    )
    return f" (exit {error.returncode}: {detail})"


def _show_ssh_assessment(*, detailed: bool = False) -> int:
    try:
        result = _make_orchestrator().run_ssh(
            section_builder=_ssh_report_section,
            findings_builder=_ssh_findings,
            ssh_collector=collect_ssh_config,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        result = _make_orchestrator()._result(
            sections=(ReportSection("SSH", status="NOT_ASSESSED", message=_ssh_error_message(error)),),
            scope=("SSH configuration",), coverage=AssessmentCoverage.PARTIAL, review_items=1,
        )
    result = _combine_results(result, _run_ssh_host_key_result(details=detailed))
    _render_result(result, details=detailed)
    return len(result.findings)


def _ssh_findings(ssh_config: SSHConfig) -> tuple[Finding, ...]:
    """Run the existing SSH checks and return their findings unchanged."""
    return (
        *check_ssh_root_login(ssh_config),
        *check_ssh_password_authentication(ssh_config),
        *check_ssh_empty_passwords(ssh_config),
        *check_ssh_public_key_authentication(ssh_config),
    )


def _service_report_section(services: tuple[Service, ...], *, detailed: bool = False) -> ReportSection:
    active = sum(service.state == "active" for service in services)
    inactive = sum(service.state == "inactive" for service in services)
    other_state = len(services) - active - inactive
    enabled = sum(service.enabled is True for service in services)
    disabled = sum(service.enabled is False for service in services)
    unknown_enabled = len(services) - enabled - disabled
    startup_services = tuple(
        _display_value(service.name)
        for service in services
        if service.state == "active" and service.unit_file_state == "enabled"
    )
    limit = 60 if detailed else 8
    visible = startup_services[:limit]
    if visible:
        items = visible
    else:
        items = ("No active, startup-enabled services found.",)
    if len(startup_services) > limit:
        items += (f"{len(startup_services) - limit} additional service(s) omitted; use --details to list them.",)
    return ReportSection(
        title="SERVICES",
        facts=(
            ("Units", str(len(services))),
            ("State", f"{active} active · {inactive} inactive · {other_state} other/unknown"),
            ("Startup enabled", f"{enabled} yes · {disabled} no · {unknown_enabled} unknown"),
        ),
        items=items,
        items_label=("Active now and enabled to start at boot:" if startup_services else None),
        footer=("Use scan service --details to inspect unit-file ownership and permissions." if not detailed else "Unit-file metadata checks are performed separately below."),
    )


def _ssh_report_section(config: SSHConfig) -> ReportSection:
    root_login = {
        "yes": "yes",
        "no": "no",
        "prohibit-password": "key login only",
        "forced-commands-only": "restricted key login only",
    }[config.permit_root_login]
    return ReportSection(
        title="SSH",
        table=(
            ("Root login", root_login),
            ("Password authentication", "yes" if config.password_authentication else "no"),
            ("Public-key authentication", "yes" if config.public_key_authentication else "no"),
            ("Empty passwords", "yes" if config.permit_empty_passwords else "no"),
        ),
        footer="Values are global sshd options; Match rules may vary by connection.",
    )


def _show_scan(*, detailed: bool = False) -> None:
    """Run the full assessment and merge supplementary read-only checks."""
    services_seen: list[tuple[Service, ...]] = []

    def service_section(services: tuple[Service, ...]) -> ReportSection:
        services_seen.append(services)
        return _service_report_section(services, detailed=detailed)

    try:
        result = _make_orchestrator().run_full_scan(
            users_section_builder=lambda users, sudo: _user_report_section(users, sudo, detailed=detailed),
            filesystem_section_builder=lambda results, assessment, coverage, setid: _filesystem_report_section(
                results, assessment, coverage, setid, detailed_findings=detailed
            ),
            ssh_section_builder=_ssh_report_section,
            ssh_findings_builder=_ssh_findings,
            service_section_builder=service_section,
            host_section_builder=lambda info: ReportSection(
                title="SYSTEM",
                facts=(
                    ("Hostname", _display_value(info.hostname)),
                    ("Distribution", _display_value(info.distribution) + (f" ({_display_value(info.distribution_version)})" if info.distribution_version else "")),
                    ("Kernel", _display_value(info.kernel_release)),
                    ("Architecture", _display_value(info.architecture)),
                    ("Uptime", _format_uptime(info.uptime_seconds)),
                ),
            ),
            host_collector=collect_system_info,
            services_collector=collect_services,
            users_collector=collect_local_users,
            sudo_collector=collect_sudo_privileges,
            sensitive_file_collector=collect_sensitive_file_metadata,
            sensitive_file_assessor=assess_sensitive_files,
            setid_collector=collect_setid_files,
            setid_assessor=assess_setid_files,
            ssh_collector=collect_ssh_config,
        )
    except NotImplementedError:
        result = _make_orchestrator()._result(
            sections=(ReportSection("SYSTEM", status="NOT_ASSESSED", message="Full host assessment is supported on Linux only."),),
            scope=("system facts", "full assessment"),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )
        _render_result(result, details=detailed)
        return
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        result = _make_orchestrator()._result(
            sections=(ReportSection("SYSTEM", status="NOT_ASSESSED", message=f"Host information could not be collected reliably: {_display_value(str(error))}"),),
            scope=("system facts", "full assessment"),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )
        _render_result(result, details=detailed)
        return

    extras = [
        _run_hardening_result(details=detailed),
        _run_network_result(details=detailed),
        _run_ssh_host_key_result(details=detailed),
    ]
    if services_seen:
        # Collect unit metadata once for all names already captured by the service scan.
        extras.append(_run_unit_file_result(services_seen[0], details=detailed))
    result = _combine_results(result, *extras)
    _render_result(result, details=detailed)

def _show_presentation() -> None:
    """Render the Vulpnix shell header and current privilege mode."""
    top = "╭" + "─" * _TITLE_BOX_WIDTH + "╮"
    bottom = "╰" + "─" * _TITLE_BOX_WIDTH + "╯"
    context = current_privilege_context()
    print(_PRESENTATION_INDENT + accent(top))
    for label in ("VULPNIX", "Linux security assessment"):
        padding = " " * max(_TITLE_BOX_WIDTH - len(label) - 2, 0)
        print(_PRESENTATION_INDENT + accent(f"│ {label}{padding} │", bold=label == "VULPNIX"))
    print(_PRESENTATION_INDENT + accent(bottom))
    print(_PRESENTATION_INDENT + f"Mode: {context.mode} · UID: {context.uid}")
    if not context.privileged:
        print(_PRESENTATION_INDENT + "Some checks may require elevated privileges: sudo vulpnix")
    print()
    if terminal_size()[0] >= 105:
        for row in _FOX_ART:
            print(_PRESENTATION_INDENT + accent(row))
    else:
        print(_PRESENTATION_INDENT + accent("[ VULPNIX ]", bold=True))
        print(_PRESENTATION_INDENT + "Terminal width is too narrow for the full logo.")


_COMMANDS = (
    Command("help", "GENERAL", "Commands", _show_help),
    Command("info", "GENERAL", "About", _show_info),
    Command("version", "GENERAL", "Version", _show_version),
    Command("scan", "ASSESSMENT", "Full Linux assessment", _show_scan),
    Command("clear", "SESSION", "Refresh screen", _clear_screen),
    Command("exit", "SESSION", "Quit", None),
)
_COMMANDS_BY_NAME = {command.name: command for command in _COMMANDS}
_COMPLETIONS = (
    "help",
    "info",
    "version",
    "scan",
    "scan --details",
    "scan host",
    "scan host --details",
    "scan hardening",
    "scan hardening --details",
    "scan users",
    "scan users --details",
    "scan service",
    "scan service --details",
    "scan ssh",
    "scan ssh --details",
    "scan filesystem",
    "scan filesystem --details",
    "scan network",
    "scan network --details",
    "clear",
    "exit",
)


def _command_completions(prefix: str) -> tuple[str, ...]:
    """Return Vulpnix commands matching the text before the cursor."""
    candidates = _COMPLETIONS
    if prefix == "scan":
        candidates = tuple(item for item in candidates if item != "scan")
    elif prefix.startswith("scan "):
        candidates = tuple(item for item in candidates if item.startswith("scan "))
    return tuple(item for item in candidates if item.startswith(prefix))


def _common_completion(candidates: tuple[str, ...]) -> str:
    if not candidates:
        return ""
    common = candidates[0]
    for candidate in candidates[1:]:
        length = 0
        for left, right in zip(common, candidate):
            if left != right:
                break
            length += 1
        common = common[:length]
    return common


def _dispatch_command(command_name: str) -> bool:
    """Dispatch one known command; return False when the shell should exit."""
    parts = command_name.split()
    if parts and parts[0] == "scan":
        if parts in (["scan"], ["scan", "--details"]):
            _show_scan(detailed=len(parts) == 2)
            return True
        if parts == ["scan", "host"]:
            _show_host_assessment("HOST DETAILS")
            return True
        if parts == ["scan", "host", "--details"]:
            _show_host_assessment("HOST DETAILS", details=True)
            return True
        if parts in (["scan", "hardening"], ["scan", "hardening", "--details"]):
            _render_result(_run_hardening_result(details=len(parts) == 3), details=len(parts) == 3)
            return True
        if parts in (["scan", "network"], ["scan", "network", "--details"]):
            _render_result(_run_network_result(details=len(parts) == 3), details=len(parts) == 3)
            return True
        if parts in (["scan", "users"], ["scan", "users", "--details"]):
            detailed = len(parts) == 3
            _show_users_assessment(detailed=detailed)
            return True
        if parts == ["scan", "service"]:
            _show_service_assessment()
            return True
        if parts == ["scan", "service", "--details"]:
            _show_service_assessment(detailed=True)
            return True
        if parts == ["scan", "ssh"]:
            _show_ssh_assessment()
            return True
        if parts == ["scan", "ssh", "--details"]:
            _show_ssh_assessment(detailed=True)
            return True
        if parts == ["scan", "filesystem"]:
            _show_filesystem_assessment()
            return True
        if parts == ["scan", "filesystem", "--details"]:
            _show_filesystem_assessment(detailed=True)
            return True
        if len(parts) > 1:
            print("Usage: scan [--details] | host [--details] | hardening [--details] | users [--details] | service [--details] | ssh [--details] | filesystem [--details] | network [--details]")
            return True

    command = _COMMANDS_BY_NAME.get(command_name)
    if command is None:
        if command_name:
            print(f"Unknown command: {command_name}. Type 'help' for commands.")
        return True

    if command.handler is None:
        print("Exiting Vulpnix.")
        return False

    command.handler()
    return True


class _TerminalCapture(io.StringIO):
    """Capture printed output while preserving terminal-aware styling."""

    def isatty(self) -> bool:
        return True


def _capture_output(callback: Callable[[], object]) -> tuple[object, str]:
    capture = _TerminalCapture()
    with redirect_stdout(capture):
        result = callback()
    return result, capture.getvalue()


def _append_output(lines: list[str], output: str) -> None:
    global _OUTPUT_LAYOUT_CACHE
    clear_sequence = "\033[2J\033[H"
    if output or clear_sequence in output:
        _OUTPUT_LAYOUT_CACHE = None
    if clear_sequence in output:
        lines.clear()
        output = output.replace(clear_sequence, "")
    if output:
        lines.extend(output.splitlines())


def _fit_output_to_width(lines: list[str], width: int) -> list[str]:
    """Reflow captured output to the current terminal width."""
    global _OUTPUT_LAYOUT_CACHE
    width = max(width, 1)
    last_line = lines[-1] if lines else ""
    cache_key = (id(lines), width, len(lines), last_line)
    if _OUTPUT_LAYOUT_CACHE is not None:
        cached_id, cached_width, cached_count, cached_last, cached_lines = (
            _OUTPUT_LAYOUT_CACHE
        )
        if cache_key == (cached_id, cached_width, cached_count, cached_last):
            return cached_lines

    fitted: list[str] = []
    for line in lines:
        if not line:
            fitted.append("")
            continue
        if "\033[" in line:
            fitted.append(clip_ansi_line(line, width))
            continue

        leading = line[: len(line) - len(line.lstrip())]
        content = line[len(leading) :]
        label_end = content.find(": ")
        if label_end >= 0:
            first_prefix = leading + content[: label_end + 2]
            if display_width(first_prefix) < width // 2:
                wrapped = wrap_text(
                    content[label_end + 2 :],
                    initial_indent=first_prefix,
                    subsequent_indent=" " * display_width(first_prefix),
                    width=width,
                )
                fitted.extend(clip_ansi_line(part, width) for part in wrapped)
                continue

        wrapped = wrap_text(
            content,
            initial_indent=leading,
            subsequent_indent=leading + "  ",
            width=width,
        )
        fitted.extend(clip_ansi_line(part, width) for part in wrapped)
    _OUTPUT_LAYOUT_CACHE = (*cache_key, fitted)
    return fitted


def _output_position_for_mouse(
    lines: list[str],
    scroll_offset: int,
    suggestions: tuple[str, ...],
    mouse_x: int,
    mouse_y: int,
) -> tuple[int, int] | None:
    """Map one-based terminal coordinates to a zero-based output cell."""
    columns, rows = terminal_size()
    rows = max(rows, 1)
    display_lines = _fit_output_to_width(lines, columns)
    visible_suggestions = suggestions[: max(rows - 2, 0)]
    page_height = max(rows - 1 - len(visible_suggestions), 0)
    visible_end = max(0, len(display_lines) - scroll_offset)
    visible_start = max(0, visible_end - page_height)
    output_row = mouse_y - 1
    visible_count = visible_end - visible_start
    if output_row < 0 or output_row >= visible_count:
        return None
    return visible_start + output_row, min(max(mouse_x - 1, 0), columns - 1)


def _render_shell(
    lines: list[str],
    command_line: str,
    cursor: int,
    scroll_offset: int,
    suggestions: tuple[str, ...] = (),
    selection: MouseTextSelection | None = None,
) -> None:
    columns, rows = terminal_size()
    rows = max(rows, 1)
    visible_suggestions = suggestions[: max(rows - 2, 0)]
    page_height = max(rows - 1 - len(visible_suggestions), 0)
    display_lines = _fit_output_to_width(lines, columns)
    visible_end = max(0, len(display_lines) - scroll_offset)
    visible_start = max(0, visible_end - page_height)
    visible_lines = display_lines[visible_start:visible_end]
    if selection is not None:
        highlighted_lines: list[str] = []
        for index, line in enumerate(visible_lines, start=visible_start):
            selected_range = selection.column_range(index)
            if selected_range is None:
                highlighted_lines.append(line)
                continue
            first_column, last_column = selected_range
            end_column = columns if last_column is None else min(columns, last_column + 1)
            highlighted_lines.append(
                highlight_columns(line, first_column, end_column)
            )
        visible_lines = highlighted_lines

    prompt = f"{accent('vulpnix>', bold=True)} "
    prompt = clip_ansi_line(prompt, columns)
    prompt_width = min(len("vulpnix> "), columns)
    frame = visible_lines[:]
    displayed_command = clip_ansi_line(command_line, max(columns - prompt_width, 0))
    prompt_row = min(len(frame), rows - 1)
    frame.insert(prompt_row, prompt + displayed_command)
    frame.extend("" for _ in range(rows - len(frame) - len(visible_suggestions)))
    frame.extend(clip_ansi_line(line, columns) for line in visible_suggestions)

    output = ["\033[H"]
    for row_number, line in enumerate(frame[:rows]):
        output.extend((line, "\033[K"))
        if row_number < rows - 1:
            output.append("\r\n")

    prompt_column = min(prompt_width + cursor + 1, max(columns, 1))
    output.append(f"\033[{prompt_row + 1};{prompt_column}H")
    sys.stdout.write("".join(output))
    sys.stdout.flush()


def _read_command(
    lines: list[str], history: list[str], scroll_offset: int
) -> tuple[str, int]:
    command_line = ""
    cursor = 0
    history_position = len(history)
    saved_line = ""
    pending_tab: tuple[str, tuple[str, ...]] | None = None
    completion_suggestions: tuple[str, ...] = ()
    selection_anchor: tuple[int, int] | None = None
    selection_active = False
    selection: MouseTextSelection | None = None

    while True:
        _render_shell(
            lines,
            command_line,
            cursor,
            scroll_offset,
            completion_suggestions,
            selection,
        )
        rendered_size = terminal_size()
        while True:
            key = read_key(timeout=0.2)
            if key is not None or terminal_size() != rendered_size:
                break
        if key is None:
            continue

        if key == "\t":
            prefix = command_line[:cursor]
            candidates = _command_completions(prefix)
            if pending_tab == (prefix, candidates) and candidates:
                completion_suggestions = (
                    accent("SUGGESTIONS"),
                    *(f"  {item}" for item in candidates),
                )
                pending_tab = None
                continue

            if not candidates:
                pending_tab = None
                continue

            common = _common_completion(candidates)
            if common != prefix:
                completed = common
                if len(candidates) == 1 and common == candidates[0]:
                    completed += " "
                command_line = completed + command_line[cursor:]
                cursor = len(completed)
                new_prefix = command_line[:cursor]
                new_candidates = _command_completions(new_prefix)
                pending_tab = (
                    (new_prefix, new_candidates) if len(new_candidates) > 1 else None
                )
            elif len(candidates) == 1 and candidates[0] == prefix:
                command_line = prefix + " " + command_line[cursor:]
                cursor += 1
                pending_tab = None
            else:
                pending_tab = (prefix, candidates)
            continue

        pending_tab = None
        completion_suggestions = ()
        if key in {"\\033[5~", "\\033[6~"}:
            columns, rows = terminal_size()
            page_height = max(rows - 2, 1)
            max_offset = max(
                0, len(_fit_output_to_width(lines, columns)) - page_height
            )
            direction = 1 if key == "\\033[5~" else -1
            scroll_offset = min(
                max_offset, max(0, scroll_offset + direction * page_height)
            )
            continue

        mouse_event = _parse_sgr_mouse_event(key)
        if mouse_event is not None:
            button, mouse_x, mouse_y, released = mouse_event
            if button & 64:
                columns, rows = terminal_size()
                page_height = max(rows - 1, 1)
                max_offset = max(
                    0, len(_fit_output_to_width(lines, columns)) - page_height
                )
                direction = 1 if button & 1 == 0 else -1
                scroll_offset = min(max_offset, max(0, scroll_offset + direction))
                continue

            position = _output_position_for_mouse(
                lines,
                scroll_offset,
                completion_suggestions,
                mouse_x,
                mouse_y,
            )
            if released:
                if selection_active and selection_anchor is not None and position is not None:
                    selection = MouseTextSelection(selection_anchor, position)
                    display_lines = _fit_output_to_width(lines, terminal_size()[0])
                    selected_text = extract_selected_text(display_lines, selection)
                    if selected_text:
                        copy_text_to_clipboard(selected_text)
                selection_active = False
                selection_anchor = None
                continue

            if button & 32:
                if selection_active and selection_anchor is not None and position is not None:
                    selection = MouseTextSelection(selection_anchor, position)
                continue

            if (button & 3) == 0:
                selection_anchor = position
                selection_active = position is not None
                selection = (
                    MouseTextSelection(position, position)
                    if position is not None else None
                )
            continue

        if key in {"\r", "\n"}:
            return command_line.strip(), 0
        if key == "\x03":
            raise KeyboardInterrupt
        if key == "\x04":
            if not command_line:
                raise EOFError
            command_line = command_line[:cursor] + command_line[cursor + 1 :]
            continue
        if key in {"\x7f", "\x08"}:
            if cursor:
                command_line = command_line[: cursor - 1] + command_line[cursor:]
                cursor -= 1
            continue
        if key == "\x01":
            cursor = 0
            continue
        if key == "\x05":
            cursor = len(command_line)
            continue
        if key == "\033[D":
            cursor = max(0, cursor - 1)
            continue
        if key == "\033[C":
            cursor = min(len(command_line), cursor + 1)
            continue
        if key in {"\033[H", "\033[1~"}:
            cursor = 0
            continue
        if key in {"\033[F", "\033[4~"}:
            cursor = len(command_line)
            continue
        if key == "\033[3~":
            command_line = command_line[:cursor] + command_line[cursor + 1 :]
            continue
        if key == "\033[A" and history_position > 0:
            if history_position == len(history):
                saved_line = command_line
            history_position -= 1
            command_line = history[history_position]
            cursor = len(command_line)
            continue
        if key == "\033[B":
            if history_position < len(history):
                history_position += 1
                command_line = (
                    history[history_position]
                    if history_position < len(history)
                    else saved_line
                )
                cursor = len(command_line)
            continue
        if len(key) == 1 and key.isprintable():
            command_line = command_line[:cursor] + key + command_line[cursor:]
            cursor += len(key)


def _run_interactive_shell() -> None:
    global _LIVE_PROGRESS
    _LIVE_PROGRESS = True
    output_lines: list[str] = []
    history: list[str] = []
    _, presentation = _capture_output(_show_presentation)
    _append_output(output_lines, presentation)

    with raw_input_mode():
        while True:
            try:
                command, _ = _read_command(output_lines, history, 0)
            except (EOFError, KeyboardInterrupt):
                _append_output(output_lines, "\nExiting Vulpnix.\n")
                _render_shell(output_lines, "", 0, 0)
                _LIVE_PROGRESS = False
                return

            entered = f"{accent('vulpnix>', bold=True)} {command}"
            output_lines.append(entered)
            if command:
                history.append(command)

            keep_running, output = _capture_output(lambda: _dispatch_command(command))
            _append_output(output_lines, output)
            if not keep_running:
                _render_shell(output_lines, "", 0, 0)
                _LIVE_PROGRESS = False
                return


def _readline_completer(text: str, state: int) -> str | None:
    """Complete full Vulpnix commands in the native terminal prompt."""
    if readline is None:
        return None
    line = readline.get_line_buffer()
    candidates = tuple(
        candidate
        for candidate in _command_completions(line)
        if candidate.startswith(line)
    )
    return candidates[state] if state < len(candidates) else None


def run_shell() -> None:
    """Run Vulpnix using the terminal's native scrollback and line input."""
    global _LIVE_PROGRESS
    _LIVE_PROGRESS = True
    interactive = sys.stdin.isatty() and sys.stdout.isatty()

    if interactive and readline is not None:
        readline.set_completer(_readline_completer)
        readline.set_completer_delims("")
        readline.parse_and_bind("tab: complete")
        prompt = f"\\001{accent('vulpnix>', bold=True)}\\002 "
    else:
        prompt = "vulpnix> "

    try:
        _show_presentation()
        while True:
            try:
                command = input(prompt).strip()
            except EOFError:
                print("\\nExiting Vulpnix.")
                return
            except KeyboardInterrupt:
                print("\\nUse 'exit' to close Vulpnix.")
                continue

            if not command:
                continue

            if interactive and readline is not None:
                readline.add_history(command)

            try:
                keep_running = _dispatch_command(command)
            except KeyboardInterrupt:
                print("\\nOperation interrupted.")
                continue

            if not keep_running:
                return
    finally:
        _LIVE_PROGRESS = False


def main() -> None:
    """Start Vulpnix in its dedicated terminal screen by default."""
    if "--plain" in sys.argv[1:]:
        run_shell()
        return

    with alternate_screen():
        _run_interactive_shell()
