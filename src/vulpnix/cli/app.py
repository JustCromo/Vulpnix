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
    collect_network_interfaces,
    collect_firewall_snapshot,
    collect_ssh_host_key_metadata,
    collect_service_unit_file_metadata,
)
from vulpnix.collectors.ssh import SSHCommandError, SSHGUnsupportedError
from vulpnix.collectors.package_audit import collect_package_audit
from vulpnix.collectors.packages import collect_package_inventory
from vulpnix.collectors.storage import collect_storage_snapshot
from vulpnix.parsers.systemd import UNIT_FILE_NON_BOOLEAN_STATES
from vulpnix.models.storage import StorageStatus
from vulpnix.rules.storage import assess_storage
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
    FirewallObservation,
    FirewallSnapshot,
    NetworkInterfaceSnapshot,
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
    color,
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

from vulpnix.cli.html_report import save_html_report
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
from vulpnix.risk import assess_findings
from vulpnix.scan.privilege import current_privilege_context
from vulpnix.cli.summary import AssessmentCoverage
from vulpnix.rules.hardening import assess_kernel_hardening
from vulpnix.rules.firewall import assess_firewall_policy
from vulpnix.scan.progress import ScanProgress, ScanStage
from vulpnix.cli.mascot import (
    MASCOT_COLUMNS,
    MASCOT_MIN_TERMINAL_HEIGHT,
    MASCOT_MIN_TERMINAL_WIDTH,
    MASCOT_ROWS,
    delete_placement_command,
    kitty_graphics_supported,
    mascot_image_path,
    placement_command,
    transmit_png,
)


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
_MASCOT_SESSION_ENABLED = False
_MASCOT_PLACEMENT_ACTIVE: bool | None = None
_MASCOT_TOP_ROW = 4
_MASCOT_RIGHT_MARGIN = 8
_MASCOT_CONTENT_GAP = 4
_WELCOME_TABLE_MARKER_PREFIX = "\x00VULPNIX_TABLE_RIGHT:"
_WELCOME_TABLE_MARKER_END = "\x00"


def _mascot_image_column(columns: int) -> int:
    """Calculate the left edge of the fixed right-hand mascot panel."""
    return columns - MASCOT_COLUMNS - _MASCOT_RIGHT_MARGIN


def _mascot_content_width(columns: int) -> int:
    """Keep text clear of the mascot while preserving a readable report width."""
    return max(1, _mascot_image_column(columns) - _MASCOT_CONTENT_GAP)


def _mascot_visible(columns: int, rows: int) -> bool:
    """Return whether the current terminal can safely display the mascot panel."""
    return (
        _MASCOT_SESSION_ENABLED
        and columns >= MASCOT_MIN_TERMINAL_WIDTH
        and rows >= MASCOT_MIN_TERMINAL_HEIGHT
        and kitty_graphics_supported()
    )


@dataclass(frozen=True)
class Command:
    """One supported Vulpnix command and its help metadata."""

    name: str
    group: str
    description: str
    handler: Callable[[], None] | None






def _show_help() -> None:
    """Print commands and descriptions in an aligned two-column layout."""
    descriptions = {
        "help": "Show available commands",
        "info": "Show project purpose and implementation status",
        "version": "Show installed version",
        "scan": "Full Linux assessment, including package CVE/advisory review (network)",
        "clear": "Clear screen and redraw the welcome presentation",
        "exit": "Close Vulpnix",
    }

    area_rows = (
        ("scan host [--details]",
         "Host facts; details include selected kernel-hardening checks"),
        ("scan hardening [--details]",
         "Read-only kernel hardening checks"),
        ("scan users [--details]",
         "User and privilege assessment; details show the complete account inventory"),
        ("scan service [--details]",
         "Services and startup state; details include unit-file metadata"),
        ("scan ssh [--details]",
         "SSH configuration and host-key metadata"),
        ("scan filesystem [--details]",
         "Sensitive file metadata and set-ID checks"),
        ("scan network [--details]",
         "Listening sockets, interfaces and firewall policy"),
        ("scan packages [--details]",
         "Installed packages and CVE/advisory review (network)"),
    )

    command_rows = tuple(
        (
            "scan [--details]" if command.name == "scan" else command.name,
            descriptions.get(command.name, command.description),
        )
        for command in _COMMANDS
    )
    option_rows = (
        ("--details", "Expand technical evidence without changing assessment rules"),
    )
    all_rows = command_rows + area_rows + option_rows
    label_width = max(len(label) for label, _ in all_rows)
    columns, _ = terminal_size()
    frame_width = max(12, min(96, columns))
    description_width = frame_width - label_width - 9

    def print_rows(rows):
        for command, description in rows:
            highlighted_command = color(
                command,
                _COMMAND_HIGHLIGHT_RGB,
                bold=True,
            )
            separator = color("│", _FRAME_BORDER_RGB)

            if description_width < 18:
                print(f"  {highlighted_command}")
                continuation_indent = "    "
                for continuation in wrap_text(
                    description,
                    max(1, frame_width - 8),
                    initial_indent=continuation_indent,
                    subsequent_indent=continuation_indent,
                ):
                    print(continuation)
                continue

            wrapped = wrap_text(description, width=description_width)
            command_padding = " " * max(
                0, label_width - display_width(command)
            )
            print(
                f"  {highlighted_command}{command_padding} "
                f"{separator} {wrapped[0]}"
            )
            for continuation in wrapped[1:]:
                print(
                    f"  {'':<{label_width}} {separator} {continuation}"
                )

    print(f"\n{accent('COMMANDS')}")
    group_names = dict.fromkeys(command.group for command in _COMMANDS)
    for group_name in group_names:
        print(f"\n{group_name}")
        print_rows(tuple(
            row for row, command in zip(command_rows, _COMMANDS)
            if command.group == group_name
        ))

    print(f"\n{accent('SCAN AREAS')}")
    print_rows(area_rows)

    print(f"\n{accent('OPTIONS')}")
    print_rows(option_rows)

    print("\nRun once with: sudo vulpnix — all shell commands inherit UID 0")

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
    """Clear the visible output and restore the welcome presentation."""
    global _MASCOT_PLACEMENT_ACTIVE
    # Clearing the terminal can invalidate Kitty's visible image placement.
    # Force a refresh on the next real shell render.
    _MASCOT_PLACEMENT_ACTIVE = False
    clear_screen()
    columns, rows = terminal_size()
    _show_presentation(kitty_mascot=_mascot_visible(columns, rows))


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


_REPORT_EXPORT_FORMAT: str | None = None
_REPORT_EXPORT_AREA: str | None = None


def _render_result(result, *, details: bool = True) -> None:
    """Render a normalized scan result with the shared terminal renderer."""
    report = ScanReport(
        host=result.host,
        sections=result.sections,
        findings=result.findings,
        scope=result.scope,
        risk_assessment=assess_findings(result.findings),
        coverage=result.coverage,
        review_items=result.review_items,
        privilege=result.privilege,
        details=details,
    )
    if _REPORT_EXPORT_FORMAT == "html":
        try:
            destination = save_html_report(
                report,
                area=_REPORT_EXPORT_AREA,
            )
        except (OSError, ValueError) as error:
            print(f"Could not save HTML report: {error}")
        else:
            print(f"HTML report saved: {destination}")
        return

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
            ("Checks passing", str(passed)),
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



def _network_interface_report_section(
    snapshot: NetworkInterfaceSnapshot, *, details: bool = False
) -> ReportSection:
    interfaces = snapshot.interfaces
    up_count = sum(item.state == "UP" for item in interfaces)
    down_count = sum(item.state == "DOWN" for item in interfaces)
    addressed = sum(bool(item.addresses) for item in interfaces)
    address_count = sum(len(item.addresses) for item in interfaces)
    limit = 60 if details else 8

    items = tuple(
        f"{item.name} · state {item.state} · "
        f"flags: {', '.join(item.flags) if item.flags else 'unavailable'} · "
        f"addresses: {', '.join(item.addresses) if item.addresses else 'none reported'}"
        for item in interfaces[:limit]
    )

    if not items:
        if snapshot.source == "unavailable":
            items = ("Interface inventory was not assessed; absence cannot be inferred.",)
        elif snapshot.review:
            items = ("No usable interface records; consult the review messages.",)
        else:
            items = ("No interface records were reported.",)
    elif len(interfaces) > limit:
        items += (
            f"{len(interfaces) - limit} additional interface(s) omitted; "
            "use --details to list more.",
        )

    if snapshot.review:
        items += tuple(f"REVIEW: {message}" for message in snapshot.review[:6])
        if len(snapshot.review) > 6:
            items += (
                f"{len(snapshot.review) - 6} additional review message(s) omitted.",
            )

    return ReportSection(
        title="NETWORK INTERFACES",
        facts=(
            ("Inventory source", snapshot.source),
            ("Interfaces", str(len(interfaces))),
            ("State UP", str(up_count)),
            ("State DOWN", str(down_count)),
            ("Interfaces with IP addresses", str(addressed)),
            ("IP addresses", str(address_count)),
        ),
        items=items,
        items_label="Local interface inventory:",
        footer="Assigned addresses and interface state do not prove internet reachability.",
    )



def _firewall_report_section(
    snapshot: FirewallSnapshot, *, details: bool = False
) -> ReportSection:
    observations = snapshot.observations
    configured = sum(item.state == "CONFIGURED" for item in observations)
    empty = sum(item.state == "EMPTY" for item in observations)
    not_assessed = sum(item.state == "NOT_ASSESSED" for item in observations)
    errors = sum(item.state == "ERROR" for item in observations)

    items = []
    represented_review = set()

    for observation in observations:
        items.append(
            f"{observation.implementation} · {observation.state} · "
            f"{observation.summary}"
        )
        if details:
            items.append(f"{observation.implementation} source: {observation.source}")
            items.extend(
                f"{observation.implementation} detail: {detail}"
                for detail in observation.details
            )
        for message in observation.review:
            represented_review.add(message)
            items.append(f"REVIEW ({observation.implementation}): {message}")

    for message in snapshot.review:
        if message not in represented_review:
            items.append(f"REVIEW: {message}")

    if not items:
        items.append(
            "Firewall state is NOT_ASSESSED; no inspection result was available."
        )

    limit = 30 if details else 8
    if len(items) > limit:
        omitted = len(items) - limit
        items = items[:limit]
        items.append(
            f"{omitted} additional firewall detail(s) omitted; use --details to list more."
        )

    return ReportSection(
        title="FIREWALL CONFIGURATION",
        facts=(
            ("Implementations observed", str(len(observations))),
            ("Reported configured", str(configured)),
            ("Reported empty", str(empty)),
            ("Not assessed", str(not_assessed)),
            ("Errors", str(errors)),
        ),
        items=tuple(items),
        items_label="Read-only firewall observations:",
        footer=(
            "Configured rules do not prove effective protection; an empty "
            "frontend does not prove that no other firewall backend applies."
        ),
    )



def _firewall_policy_report_section(
    assessment, *, details: bool = False
) -> ReportSection:
    """Render firewall observations and review findings separately."""
    observations = tuple(
        check for check in assessment.checks
        if check.startswith("POLICY OBSERVED · ")
    )
    reviews = tuple(
        check for check in assessment.checks
        if check.startswith("REVIEW · ")
    )
    limit = 30 if details else 8

    items = []
    for label, group in (
        ("POLICY OBSERVATION", observations),
        ("REVIEW FINDING", reviews),
    ):
        for check in group[:limit]:
            _, _, description = check.partition(" · ")
            items.append(f"{label} · {description}")

        omitted = len(group) - limit
        if omitted > 0:
            items.append(
                f"{omitted} additional {label.lower()}(s) omitted; "
                "use --details to list them."
            )

    if not items:
        items.append(
            "No firewall policy observations or review findings were produced."
        )

    return ReportSection(
        title="FIREWALL POLICY ANALYSIS",
        facts=(
            ("Policy observations", str(len(observations))),
            ("Review findings", str(len(assessment.findings))),
        ),
        items=tuple(items),
        items_label="Assessment results:",
        footer=(
            "Preliminary chain analysis only. It does not prove internet "
            "reachability or fully resolve interactions between chains, "
            "hooks, and firewall backends."
        ),
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
    orchestrator = _make_orchestrator()

    try:
        socket_result = orchestrator.run_network(
            collector=collect_network_snapshot,
            section_builder=lambda snapshot: _network_report_section(
                snapshot, details=details
            ),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        socket_result = orchestrator._result(
            sections=(
                ReportSection(
                    "NETWORK EXPOSURE",
                    status="NOT_ASSESSED",
                    message=f"Socket inventory is unavailable: {_display_value(str(error))}",
                ),
            ),
            scope=("listening sockets", "local bind scope"),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )

    try:
        interface_snapshot = collect_network_interfaces()
        interface_section = _network_interface_report_section(
            interface_snapshot, details=details
        )
        interface_result = orchestrator._result(
            sections=(interface_section,),
            scope=(
                "network interfaces",
                "interface IP addresses",
                "interface operational state",
            ),
            coverage=(
                AssessmentCoverage.PARTIAL
                if interface_snapshot.review
                else AssessmentCoverage.COMPLETE
            ),
            review_items=len(interface_snapshot.review),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        interface_result = orchestrator._result(
            sections=(
                ReportSection(
                    "NETWORK INTERFACES",
                    status="NOT_ASSESSED",
                    message=f"Interface inventory is unavailable: {_display_value(str(error))}",
                ),
            ),
            scope=(
                "network interfaces",
                "interface IP addresses",
                "interface operational state",
            ),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )

    try:
        firewall_snapshot = collect_firewall_snapshot()
        firewall_assessment = assess_firewall_policy(firewall_snapshot)
        firewall_section = _firewall_report_section(
            firewall_snapshot, details=details
        )
        firewall_policy_section = _firewall_policy_report_section(
            firewall_assessment, details=details
        )
        firewall_incomplete = (
            bool(firewall_snapshot.review)
            or not firewall_snapshot.observations
            or any(
                item.state in {"NOT_ASSESSED", "ERROR"}
                for item in firewall_snapshot.observations
            )
        )
        firewall_review_count = max(
            len(firewall_snapshot.review),
            1 if firewall_incomplete else 0,
        )
        firewall_result = orchestrator._result(
            sections=(firewall_section, firewall_policy_section),
            findings=firewall_assessment.findings,
            scope=(
                "firewall configuration",
                "IPv4 firewall rules",
                "IPv6 firewall rules",
                "firewall input and forwarding policy analysis",
            ),
            # Policy evaluation is intentionally partial until chain jumps,
            # all hooks, and active backend interactions are fully resolved.
            coverage=AssessmentCoverage.PARTIAL,
            review_items=(
                firewall_review_count + firewall_assessment.review_items
            ),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        firewall_result = orchestrator._result(
            sections=(
                ReportSection(
                    "FIREWALL CONFIGURATION",
                    status="NOT_ASSESSED",
                    message=f"Firewall configuration is unavailable: {_display_value(str(error))}",
                ),
                ReportSection(
                    "FIREWALL POLICY ANALYSIS",
                    status="NOT_ASSESSED",
                    message="Policy analysis could not run because firewall collection failed.",
                ),
            ),
            scope=(
                "firewall configuration",
                "IPv4 firewall rules",
                "IPv6 firewall rules",
                "firewall input and forwarding policy analysis",
            ),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )

    return _combine_results(socket_result, interface_result, firewall_result)


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

    def privilege_label(user: User) -> str:
        if user.uid == 0 or user.username in privileged_users:
            return "yes"

        sudo_result = sudo_by_account.get(user.username)
        if user.privileged is False or (
            sudo_result is not None
            and sudo_result.status is SudoPrivilegeStatus.NO_PRIVILEGES
        ):
            return "no"

        return "NOT_ASSESSED"

    inventory = tuple(
        " · ".join(
            (
                user.username,
                f"UID {user.uid}",
                f"GID {user.gid}",
                "groups: " + (", ".join(user.groups) if user.groups is not None else "Unavailable"),
                "shell: " + (user.shell or "Unavailable"),
                "privileged: " + privilege_label(user),
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
    detailed_metadata: bool = False,
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
    setid_by_path = {
        item.metadata.path: item for item in setid_coverage.files
    }
    detail_paths = set(attention_paths)
    if detailed_metadata:
        detail_paths.update(result.path for result in results)
        detail_paths.update(setid_by_path)

    for path in sorted(detail_paths):
        setid_item = setid_by_path.get(path)
        if setid_item is not None:
            if detailed_metadata:
                elf_status = (
                    "yes" if setid_item.is_elf is True
                    else "no" if setid_item.is_elf is False
                    else "NOT_ASSESSED"
                )
                if setid_item.mount_options is None:
                    mount_options = "NOT_ASSESSED"
                elif setid_item.mount_options:
                    mount_options = ", ".join(setid_item.mount_options)
                else:
                    mount_options = "(none)"

                summary = (
                    f"{_file_metadata_summary(setid_item.metadata)} · "
                    f"ELF: {elf_status} · mount options: {mount_options}"
                )
                if setid_item.reason:
                    summary += f" · review: {setid_item.reason}"
                details.append(summary)
            else:
                details.append(_file_metadata_summary(setid_item.metadata))
            continue

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




def _format_storage_size(value):
    """Format a non-negative byte count for a readable terminal report."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return "Unavailable"

    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    amount = float(value)
    unit = units[0]

    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024

    return f"{amount:.1f} {unit}" if unit != "B" else f"{value} B"


def _storage_percent(available, total):
    """Return a percentage only when both capacity measurements are valid."""
    if (
        isinstance(available, bool)
        or isinstance(total, bool)
        or not isinstance(available, int)
        or not isinstance(total, int)
        or total <= 0
        or available < 0
        or available > total
    ):
        return "Unavailable"
    return f"{available * 100.0 / total:.1f}%"


def _storage_report_section(snapshot, findings, *, details=False):
    """Build a compact capacity summary and optional mount inventory."""
    filesystems = snapshot.filesystems
    measurable = sum(
        item.total_bytes is not None and item.available_bytes is not None
        for item in filesystems
    )
    inode_measurable = sum(
        item.total_inodes is not None and item.available_inodes is not None
        for item in filesystems
    )
    low_space = sum(
        item.rule_id.startswith("STORAGE-SPACE-LOW-")
        for item in findings
    )
    low_inodes = sum(
        item.rule_id.startswith("STORAGE-INODES-LOW-")
        for item in findings
    )
    mount_reviews = sum(
        item.rule_id.startswith("FILESYSTEM-TEMP-MOUNT-OPTIONS-")
        for item in findings
    )
    unresolved = sum(item.status is FindingStatus.REVIEW for item in findings)

    items = []

    if details:
        limit = 80
        for item in filesystems[:limit]:
            options = ",".join(item.mount_options) or "(none reported)"
            inode_text = (
                f"{item.available_inodes}/{item.total_inodes} available "
                f"({_storage_percent(item.available_inodes, item.total_inodes)})"
                if item.available_inodes is not None and item.total_inodes is not None
                else "Unavailable"
            )
            items.append(
                f"{item.mount_point} | "
                f"type={item.fs_type or 'unknown'} | "
                f"source={item.source or 'unknown'} | "
                f"available={_format_storage_size(item.available_bytes)} of "
                f"{_format_storage_size(item.total_bytes)} "
                f"({_storage_percent(item.available_bytes, item.total_bytes)}) | "
                f"inodes={inode_text} | "
                f"options={options} | status={item.status.value}"
            )

        if len(filesystems) > limit:
            items.append(
                f"{len(filesystems) - limit} additional mount(s) omitted "
                "from the detail view."
            )
    elif findings:
        # Finding titles are already displayed in the report's attention area.
        # Avoid repeating all of them again inside this section.
        items.append(
            f"{len(findings)} storage review item(s) appear in the assessment findings."
        )
    elif snapshot.status is StorageStatus.COLLECTED:
        items.append(
            "No configured storage review thresholds were crossed in the "
            "measurements available."
        )
    else:
        items.append(
            "Storage coverage is incomplete. Unavailable measurements are "
            "not considered healthy."
        )

    messages = snapshot.messages
    message_limit = 10 if details else 3
    items.extend(f"REVIEW: {message}" for message in messages[:message_limit])
    if len(messages) > message_limit:
        items.append(
            f"{len(messages) - message_limit} additional collector message(s) omitted."
        )

    return ReportSection(
        title="DISK & FILESYSTEM CAPACITY",
        status=(
            None
            if snapshot.status is StorageStatus.COLLECTED
            else snapshot.status.value
        ),
        facts=(
            ("Mounted filesystems", str(len(filesystems))),
            ("Capacity measurable", str(measurable)),
            ("Inode counts measurable", str(inode_measurable)),
            ("Low available storage", str(low_space)),
            ("Low available inodes", str(low_inodes)),
            ("Mount-option reviews", str(mount_reviews)),
            ("Storage findings to review", str(unresolved)),
            ("Collection status", snapshot.status.value),
        ),
        items=tuple(items),
        items_label=(
            "Mount inventory (expanded):" if details
            else "Storage summary:"
        ),
        footer=(
            "Low capacity indicates a possible availability problem, not by "
            "itself a security vulnerability. Mount-option checks are contextual."
        ),
    )


def _run_storage_result(*, details=False):
    """Collect and assess mounted filesystems as an independent scan area."""
    orchestrator = _make_orchestrator()
    scope = (
        "mounted filesystem inventory",
        "storage capacity",
        "inode availability",
        "temporary filesystem mount options",
    )

    try:
        snapshot = collect_storage_snapshot()
        findings = assess_storage(snapshot)
    except (
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ) as error:
        result = orchestrator._result(
            sections=(
                ReportSection(
                    "DISK & FILESYSTEM CAPACITY",
                    status="NOT_ASSESSED",
                    message=(
                        "Storage assessment could not be completed: "
                        f"{_display_value(str(error))}"
                    ),
                ),
            ),
            scope=scope,
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )
        return result

    section = _storage_report_section(snapshot, findings, details=details)
    complete = snapshot.status is StorageStatus.COLLECTED

    return orchestrator._result(
        sections=(section,),
        findings=findings,
        scope=scope,
        coverage=(
            AssessmentCoverage.COMPLETE
            if complete
            else AssessmentCoverage.PARTIAL
        ),
        review_items=(
            len(snapshot.messages)
            + (
                1
                if snapshot.status is StorageStatus.NOT_ASSESSED
                and not snapshot.messages
                else 0
            )
        ),
    )

def _show_filesystem_assessment(*, detailed: bool = False) -> None:
    """Run M4 file checks and M7 mounted-filesystem capacity checks."""
    def build_section(results, assessment, setid_coverage, setid_assessment):
        return _filesystem_report_section(
            results,
            assessment,
            setid_coverage,
            setid_assessment,
            detailed_findings=detailed,
            detailed_metadata=detailed,
        )

    try:
        result = _make_orchestrator().run_filesystem(
            section_builder=build_section,
            sensitive_file_collector=collect_sensitive_file_metadata,
            sensitive_file_assessor=assess_sensitive_files,
            setid_collector=collect_setid_files,
            setid_assessor=assess_setid_files,
        )
    except (OSError, UnicodeError, ValueError) as error:
        result = _make_orchestrator()._result(
            sections=(
                ReportSection(
                    "FILESYSTEM",
                    status="NOT_ASSESSED",
                    message=(
                        "Filesystem checks could not be fully assessed: "
                        f"{_display_value(str(error))}"
                    ),
                ),
            ),
            scope=("filesystem metadata", "set-ID files"),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )

    result = _combine_results(
        result,
        _run_storage_result(details=detailed),
    )
    _render_result(result, details=detailed)



def _ssh_error_message(error: Exception) -> str:
    if isinstance(error, FileNotFoundError):
        return "OpenSSH server (sshd) is not installed."
    if isinstance(error, subprocess.TimeoutExpired):
        return "sshd did not return configuration in time."
    if isinstance(error, SSHGUnsupportedError):
        detail = _ssh_command_detail(error)
        option = getattr(error, "option", "-G")
        return (
            f"sshd {option} is not supported by this OpenSSH installation."
            f"{detail}"
        )
    if isinstance(error, SSHCommandError):
        option = getattr(error, "option", "-G")
        return f"sshd {option} failed{_ssh_command_detail(error)}."
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
    non_boolean_enabled = sum(
        service.enabled is None
        and (service.unit_file_state or "").strip().lower()
        in UNIT_FILE_NON_BOOLEAN_STATES
        for service in services
    )
    unknown_enabled = len(services) - enabled - disabled - non_boolean_enabled
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
            (
                "Startup enabled",
                f"{enabled} yes · {disabled} no · "
                f"{non_boolean_enabled} non-boolean · {unknown_enabled} unknown",
            ),
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




def _package_inventory_report_section(inventory, *, details=False):
    """Build a report section for locally installed package metadata."""
    limit = 60 if details else 8
    packages = inventory.packages

    items = tuple(
        f"{package.name} · {package.version}"
        + (f" · {package.architecture}" if package.architecture else "")
        for package in packages[:limit]
    )

    if not items:
        items = ("No usable installed-package records were collected.",)

    if len(packages) > limit:
        items += (
            f"{len(packages) - limit} additional package(s) omitted; "
            "use --details to expand the inventory.",
        )

    items += tuple(f"REVIEW: {message}" for message in inventory.messages)

    return ReportSection(
        title="SOFTWARE INVENTORY",
        status=None if inventory.status == "OK" else inventory.status,
        facts=(
            ("Distribution", inventory.distribution_name),
            ("Distribution ID", inventory.distribution_id or "Unavailable"),
            ("Release", inventory.release or "Unavailable"),
            ("Package manager", inventory.manager),
            ("Installed packages", str(len(packages))),
            ("Inventory status", inventory.status),
        ),
        items=items,
        items_label="Installed packages (sample):",
        footer=(
            "Inventory records describe installed package metadata; "
            "they do not establish whether packages are free from vulnerabilities."
        ),
    )


def _package_audit_report_section(audit, *, details=False):
    """Build a report section for package advisory correlation."""
    findings = audit.findings
    limit = 40 if details else 10

    confirmed = sum(item.status is FindingStatus.FAIL for item in findings)
    review = sum(item.status is FindingStatus.REVIEW for item in findings)

    item_lines: list[str] = []

    for item in findings[:limit]:
        item_lines.append(
            f"[{item.status.value}] {item.rule_id}: {item.title}"
        )

        if not details:
            continue

        for cve in getattr(item, "cves", ()) or ():
            cve_id = str(
                getattr(cve, "cve_id", "") or "CVE identifier unavailable"
            )
            scores = getattr(cve, "cvss", ()) or ()

            if not scores:
                item_lines.append(f"    {cve_id}: CVSS unavailable")
                continue

            for score in scores:
                version = str(getattr(score, "version", "unknown") or "unknown")
                severity_value = getattr(score, "severity", "")
                severity = str(
                    getattr(severity_value, "value", severity_value) or "UNKNOWN"
                ).upper()

                try:
                    base_score = float(score.base_score)
                except (AttributeError, TypeError, ValueError):
                    item_lines.append(f"    {cve_id}: CVSS score unavailable")
                    continue

                item_lines.append(
                    f"    {cve_id}: CVSS {version} "
                    f"{base_score:.1f} — {severity}"
                )

                source = str(getattr(score, "source", "") or "").strip()
                if source:
                    item_lines.append(f"      Source: {source}")

                vector = str(getattr(score, "vector", "") or "").strip()
                if vector:
                    item_lines.append(f"      Vector: {vector}")

    items = tuple(item_lines)

    if not items:
        items = (
            "No matching affected-package records were returned by this source. "
            "This is not proof that the system has no vulnerabilities.",
        )

    if len(findings) > limit:
        items += (
            f"{len(findings) - limit} additional advisory finding(s) omitted; "
            "use --details to expand this section.",
        )

    items += tuple(f"REVIEW: {message}" for message in audit.messages)

    return ReportSection(
        title="PACKAGE VULNERABILITY AUDIT",
        status=None if audit.status == "OK" else audit.status,
        facts=(
            ("Advisory source", audit.source),
            ("Packages checked", str(audit.packages_checked)),
            ("Advisory findings", str(len(findings))),
            ("Confirmed matches", str(confirmed)),
            ("Review matches", str(review)),
            ("Audit status", audit.status),
        ),
        items=items,
        items_label="Advisory correlation results:",
        footer=(
            "Coverage depends on the selected source and supported ecosystem. "
            "No matching result is not proof of absence."
        ),
    )



def _run_package_result(*, details=False):
    """Run local package inventory and correlate it with advisory sources."""
    orchestrator = _make_orchestrator()

    try:
        inventory = collect_package_inventory()
    except (
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ) as error:
        return orchestrator._result(
            sections=(
                ReportSection(
                    "SOFTWARE INVENTORY",
                    status="ERROR",
                    message=(
                        "Package inventory failed: "
                        f"{_display_value(str(error))}"
                    ),
                ),
            ),
            scope=("installed software inventory",),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )

    inventory_result = orchestrator._result(
        sections=(
            _package_inventory_report_section(inventory, details=details),
        ),
        scope=("installed software inventory",),
        coverage=(
            AssessmentCoverage.COMPLETE
            if inventory.status == "OK"
            else AssessmentCoverage.PARTIAL
        ),
        review_items=(
            len(inventory.messages)
            + (1 if inventory.status not in {"OK", "PARTIAL"} else 0)
        ),
    )

    try:
        audit = collect_package_audit(inventory)
    except (
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ) as error:
        audit_result = orchestrator._result(
            sections=(
                ReportSection(
                    "PACKAGE VULNERABILITY AUDIT",
                    status="ERROR",
                    message=(
                        "Package advisory assessment failed: "
                        f"{_display_value(str(error))}"
                    ),
                ),
            ),
            scope=("package vulnerability correlation",),
            coverage=AssessmentCoverage.PARTIAL,
            review_items=1,
        )
        return _combine_results(inventory_result, audit_result)

    audit_result = orchestrator._result(
        sections=(
            _package_audit_report_section(audit, details=details),
        ),
        findings=audit.findings,
        scope=("package vulnerability correlation",),
        coverage=(
            AssessmentCoverage.COMPLETE
            if audit.status == "OK"
            else AssessmentCoverage.PARTIAL
        ),
        review_items=(
            len(audit.messages)
            + (1 if audit.status != "OK" and not audit.messages else 0)
        ),
    )

    return _combine_results(inventory_result, audit_result)


def _show_packages_assessment(*, detailed=False):
    """Display package inventory and the remote CVE/advisory audit."""
    result = _run_package_result(details=detailed)
    _render_result(result, details=detailed)

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
                results, assessment, coverage, setid, detailed_findings=detailed, detailed_metadata=detailed
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
        _run_storage_result(details=detailed),
    ]
    if services_seen:
        # Collect unit metadata once for all names already captured by the service scan.
        extras.append(_run_unit_file_result(services_seen[0], details=detailed))
    result = _combine_results(result, *extras)
    result = _combine_results(
        result,
        _run_package_result(details=detailed),
    )
    _render_result(result, details=detailed)


def _show_presentation(*, kitty_mascot: bool = False) -> None:
    """Render a coordinated, width-aware Vulpnix welcome table."""
    context = current_privilege_context()
    columns, rows = terminal_size()
    indent = _PRESENTATION_INDENT

    graphic_layout = (
        kitty_mascot
        and columns >= MASCOT_MIN_TERMINAL_WIDTH
        and rows >= MASCOT_MIN_TERMINAL_HEIGHT
    )
    available_width = (
        _mascot_content_width(columns) - len(indent)
        if graphic_layout
        else columns - len(indent) - 1
    )
    box_width = max(5, min(96, available_width))
    inner_width = max(1, box_width - 4)

    def border(label: str, first: str, last: str) -> None:
        label = label[:max(1, box_width - 8)]
        prefix = f"{first}─ ✦ {label} "
        fill = max(0, box_width - display_width(prefix) - display_width(last))
        print(indent + accent(prefix + "─" * fill + last, bold=True))

    def row(value: str = "") -> None:
        parts = wrap_text(value, width=inner_width) if value else [""]
        for part in parts:
            padding = " " * max(0, inner_width - display_width(part))
            print(indent + "│ " + part + padding + " " + f"{_WELCOME_TABLE_MARKER_PREFIX}{box_width}{_WELCOME_TABLE_MARKER_END}")

    label_width = min(10, max(3, inner_width // 4))
    value_width = max(1, inner_width - label_width - 1)

    def labelled_row(label: str, value: str) -> None:
        key = label[:label_width].ljust(label_width)
        chunks = wrap_text(value, width=value_width) or [""]
        for index, chunk in enumerate(chunks):
            key_text = accent(key, bold=True) if index == 0 else " " * label_width
            padding = " " * max(0, value_width - display_width(chunk))
            print(indent + "│ " + key_text + " " + chunk + padding + " " + f"{_WELCOME_TABLE_MARKER_PREFIX}{box_width}{_WELCOME_TABLE_MARKER_END}")

    border("VULPNIX · LINUX HOST SECURITY", "╭", "╮")
    row()
    row("Evidence-based security assessment for Linux hosts.")
    row("Verified findings. Clear next steps. Honest coverage.")
    row("Missing or inconclusive evidence is never a pass.")
    row()

    border("ABOUT", "├", "┤")
    row("Vulpnix inspects Linux configuration and selected security controls.")
    row("It distinguishes verified issues, items needing review, and")
    row("checks that could not be completed reliably.")
    row()

    border("QUICK START", "├", "┤")
    labelled_row("help", "Explore available commands and options")
    labelled_row("scan", "Run a full Linux host assessment")
    labelled_row("info", "Learn about Vulpnix")
    labelled_row("clear", "Refresh this welcome screen")
    row()

    border("SESSION", "├", "┤")
    labelled_row("MODE", f"{context.mode} · UID {context.uid}")
    if not context.privileged:
        labelled_row("PRIVILEGES", "Some checks need elevated access")
        labelled_row("", "Start with: sudo vulpnix")
    row()
    print(indent + accent("╰" + "─" * (box_width - 2) + "╯", bold=True))



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
    "scan packages",
    "scan packages --details",
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

_SCAN_AREAS = (
    "host",
    "hardening",
    "users",
    "service",
    "ssh",
    "filesystem",
    "network",
    "packages",
)
_COMPLETIONS += (
    "scan --format html",
    "scan --details --format html",
    *(f"scan {area} --format html" for area in _SCAN_AREAS),
    *(f"scan {area} --details --format html" for area in _SCAN_AREAS),
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
        global _REPORT_EXPORT_FORMAT, _REPORT_EXPORT_AREA

        usage = (
            "Usage: scan [--details] [--format html] | "
            "scan <area> [--details] [--format html] "
            "(areas: host, hardening, users, service, ssh, filesystem, "
            "network, packages)"
        )

        area = None
        detailed = False
        output_format = None
        invalid = False
        index = 1

        while index < len(parts):
            token = parts[index]

            if token == "--details":
                if detailed:
                    invalid = True
                detailed = True
                index += 1
            elif token == "--format":
                if index + 1 >= len(parts):
                    invalid = True
                    index += 1
                else:
                    requested_format = parts[index + 1]
                    if output_format is not None or requested_format != "html":
                        invalid = True
                    else:
                        output_format = requested_format
                    index += 2
            elif token.startswith("--"):
                invalid = True
                index += 1
            elif token not in _SCAN_AREAS or area is not None:
                invalid = True
                index += 1
            else:
                area = token
                index += 1

        if invalid:
            print(usage)
            return True

        previous_format = _REPORT_EXPORT_FORMAT
        previous_area = _REPORT_EXPORT_AREA
        _REPORT_EXPORT_FORMAT = output_format
        _REPORT_EXPORT_AREA = area

        try:
            if area is None:
                _show_scan(detailed=detailed)
            elif area == "host":
                if detailed:
                    _show_host_assessment("HOST DETAILS", details=True)
                else:
                    _show_host_assessment("HOST DETAILS")
            elif area == "hardening":
                _render_result(
                    _run_hardening_result(details=detailed),
                    details=detailed,
                )
            elif area == "network":
                _render_result(
                    _run_network_result(details=detailed),
                    details=detailed,
                )
            elif area == "users":
                _show_users_assessment(detailed=detailed)
            elif area == "service":
                if detailed:
                    _show_service_assessment(detailed=True)
                else:
                    _show_service_assessment()
            elif area == "ssh":
                if detailed:
                    _show_ssh_assessment(detailed=True)
                else:
                    _show_ssh_assessment()
            elif area == "filesystem":
                if detailed:
                    _show_filesystem_assessment(detailed=True)
                else:
                    _show_filesystem_assessment()
            elif area == "packages":
                if detailed:
                    _show_packages_assessment(detailed=True)
                else:
                    _show_packages_assessment()
        finally:
            _REPORT_EXPORT_FORMAT = previous_format
            _REPORT_EXPORT_AREA = previous_area

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



_COMMAND_FRAME_START_PREFIX = "\x00VULPNIX_COMMAND_FRAME:"
_COMMAND_FRAME_END_MARKER = "\x00VULPNIX_COMMAND_FRAME_END\x00"
_FRAME_BORDER_RGB = (113, 128, 150)
_COMMAND_HIGHLIGHT_RGB = (196, 181, 253)


def _command_frame_title(command: str) -> str | None:
    """Map an entered command to a stable, human-readable frame title."""
    parts = command.strip().split()
    if not parts:
        return None

    first = parts[0].lower()
    if first == "clear":
        return None

    if first == "scan":
        if len(parts) > 1 and parts[1] != "--details":
            area = "".join(
                character
                for character in parts[1].upper()
                if character.isalnum() or character in "-_"
            )
            if area:
                return f"SCAN / {area}"
        return "SCAN"

    return {
        "help": "HELP",
        "info": "INFO",
        "version": "VERSION",
        "exit": "EXIT",
    }.get(first, "COMMAND")


def _strip_terminal_styles(text: str) -> str:
    """Remove CSI styling sequences for layout decisions."""
    result: list[str] = []
    index = 0

    while index < len(text):
        if (
            text[index] == "\x1b"
            and index + 1 < len(text)
            and text[index + 1] == "["
        ):
            index += 2
            while index < len(text):
                character = text[index]
                index += 1
                if "@" <= character <= "~":
                    break
            continue

        result.append(text[index])
        index += 1

    return "".join(result)


def _is_command_frame_heading(line: str, content_width: int) -> bool:
    """Recognize concise uppercase report headings for internal separators."""
    plain = _strip_terminal_styles(line).strip()
    letters = [character for character in plain if character.isalpha()]

    return (
        bool(letters)
        and not any(character.islower() for character in letters)
        and display_width(plain) <= min(content_width, 44)
    )


def _wrap_command_frame_line(line: str, width: int) -> list[str]:
    """Wrap output without losing a uniform ANSI style on continuation lines."""
    width = max(1, width)
    if display_width(line) <= width:
        return [line.rstrip()]

    reset = "\033[0m"
    prefix_parts = []
    index = 0

    while line.startswith("\033[", index):
        end = line.find("m", index + 2)
        if end < 0:
            break
        prefix_parts.append(line[index:end + 1])
        index = end + 1

    prefix = "".join(prefix_parts)
    body = line[index:]
    suffix = ""

    if body.endswith(reset):
        body = body[:-len(reset)]
        suffix = reset

    # The report uses one SGR prefix and one reset for status-colored lines.
    # Duplicate that style for each wrapped row, keeping indentation intact.
    if prefix and "\033[" not in body:
        leading = body[:len(body) - len(body.lstrip(" "))]
        available = max(1, width - display_width(leading))
        content = body[len(leading):]
        chunks = wrap_text(content, available)
        if leading:
            chunks = [leading + chunk for chunk in chunks]
        return [prefix + chunk + suffix for chunk in chunks]

    # Mixed-style lines are rare; use their visible text for safe layout.
    plain = _strip_terminal_styles(line)
    leading = plain[:len(plain) - len(plain.lstrip(" "))]
    if leading and display_width(leading) < width:
        available = max(1, width - display_width(leading))
        return [
            leading + chunk
            for chunk in wrap_text(plain[len(leading):], available)
        ]
    return wrap_text(plain, width)

def _render_command_frame(
    title: str,
    body_lines: list[str],
    width: int,
) -> list[str]:
    """Draw a closed command frame using restrained, consistent colors."""
    border_rgb = (113, 128, 150)
    width = max(1, min(width, 96))

    if width < 12:
        plain_title = f"VULPNIX / {title}"
        return [
            *_wrap_command_frame_line(plain_title, width),
            *(
                part
                for line in body_lines
                for part in _wrap_command_frame_line(line, width)
            ),
        ]

    label = f"VULPNIX / {title}"
    maximum_label_width = max(
        1,
        width - display_width("╭─ ") - display_width(" ") - display_width("╮"),
    )
    if display_width(label) > maximum_label_width:
        label = label[:maximum_label_width]

    prefix = f"╭─ {label} "
    fill = max(0, width - display_width(prefix) - display_width("╮"))
    top = (
        color("╭─ ", border_rgb, bold=True)
        + accent(label, bold=True)
        + color(" " + "─" * fill + "╮", border_rgb, bold=True)
    )
    divider = color("├" + "─" * (width - 2) + "┤", border_rgb)
    bottom = color("╰" + "─" * (width - 2) + "╯", border_rgb)
    inner_width = width - 4

    def boxed_row(text: str) -> str:
        padding = max(0, inner_width - display_width(text))
        return (
            color("│", border_rgb)
            + " "
            + text
            + " " * padding
            + " "
            + color("│", border_rgb)
        )

    normalized: list[str] = []
    for line in body_lines:
        if not _strip_terminal_styles(line).strip():
            if normalized and normalized[-1] != "":
                normalized.append("")
        else:
            normalized.append(line)

    while normalized and not normalized[0]:
        normalized.pop(0)
    while normalized and not normalized[-1]:
        normalized.pop()

    rows = [top, divider]
    last_kind = "divider"

    for line in normalized:
        if not line:
            if last_kind not in {"divider", "blank"}:
                rows.append(boxed_row(""))
                last_kind = "blank"
            continue

        if _is_command_frame_heading(line, inner_width):
            if last_kind == "blank":
                rows.pop()
                last_kind = "content"
            if last_kind != "divider":
                rows.append(divider)
                last_kind = "divider"

            rows.append(boxed_row(line))
            rows.append(divider)
            last_kind = "divider"
            continue

        for wrapped in _wrap_command_frame_line(line, inner_width):
            rows.append(boxed_row(wrapped))
            last_kind = "content"

    if len(rows) > 2 and last_kind == "divider":
        rows.pop()

    rows.append(bottom)
    return rows

def _render_command_sections(lines: list[str], width: int) -> list[str]:
    """Turn internal command-frame markers into boxes at the current width."""
    rendered: list[str] = []
    index = 0

    while index < len(lines):
        line = lines[index]
        if not line.startswith(_COMMAND_FRAME_START_PREFIX):
            rendered.append(line)
            index += 1
            continue

        title = line[len(_COMMAND_FRAME_START_PREFIX):].split("\x00", 1)[0]
        body: list[str] = []
        index += 1

        while (
            index < len(lines)
            and lines[index] != _COMMAND_FRAME_END_MARKER
        ):
            body.append(lines[index])
            index += 1

        if index >= len(lines):
            # Incomplete markers should never leak into the user's display.
            rendered.extend(body)
            break

        rendered.extend(_render_command_frame(title, body, width))
        index += 1

    return rendered


def _append_output(
    lines: list[str],
    output: str,
    *,
    title: str | None = None,
) -> None:
    """Append captured output, deferring command framing until terminal layout."""
    global _OUTPUT_LAYOUT_CACHE

    clear_sequence = "\033[2J\033[H"
    if output or clear_sequence in output:
        _OUTPUT_LAYOUT_CACHE = None

    if clear_sequence in output:
        lines.clear()
        output = output.replace(clear_sequence, "")
        title = None

    if output:
        if title:
            lines.append(f"{_COMMAND_FRAME_START_PREFIX}{title}\x00")
        lines.extend(output.splitlines())
        if title:
            lines.append(_COMMAND_FRAME_END_MARKER)

def _fit_output_to_width(
    lines: list[str],
    width: int,
    *,
    reserve_mascot: bool | None = None,
) -> list[str]:
    """Reflow shell text, optionally reserving space for the mascot panel."""
    global _OUTPUT_LAYOUT_CACHE
    width = max(width, 1)

    if reserve_mascot is None:
        _, rows = terminal_size()
        reserve_mascot = _mascot_visible(width, rows)

    if reserve_mascot:
        width = min(width, _mascot_content_width(width))

    last_line = lines[-1] if lines else ""
    cache_key = (id(lines), width, len(lines), last_line)

    if _OUTPUT_LAYOUT_CACHE is not None:
        cached_id, cached_width, cached_count, cached_last, cached_lines = (
            _OUTPUT_LAYOUT_CACHE
        )
        if cache_key == (cached_id, cached_width, cached_count, cached_last):
            return cached_lines

    formatted_lines = _render_command_sections(lines, width)
    fitted: list[str] = []
    for line in formatted_lines:
        if _WELCOME_TABLE_MARKER_PREFIX in line:
            marker_start = line.index(_WELCOME_TABLE_MARKER_PREFIX)
            marker_end = line.find(
                _WELCOME_TABLE_MARKER_END,
                marker_start + len(_WELCOME_TABLE_MARKER_PREFIX),
            )
            if marker_end >= 0:
                raw_width = line[
                    marker_start + len(_WELCOME_TABLE_MARKER_PREFIX):marker_end
                ]
                content = line[:marker_start]
                marker = line[marker_start:marker_end + len(_WELCOME_TABLE_MARKER_END)]
                try:
                    table_width = int(raw_width)
                except ValueError:
                    table_width = 0

                if table_width > 0 and len(_PRESENTATION_INDENT) + table_width <= width:
                    fitted.append(content + marker)
                else:
                    # When the terminal is too narrow, drop the right-edge
                    # marker and let normal wrapping handle the text.
                    fitted.extend(wrap_text(content.rstrip(), width=width))
                continue
        if not line:
            fitted.append("")
            continue

        if "\033[" in line:
            fitted.append(clip_ansi_line(line, width))
            continue

        leading = line[:len(line) - len(line.lstrip())]
        content = line[len(leading):]
        label_end = content.find(": ")

        if label_end >= 0:
            first_prefix = leading + content[:label_end + 2]
            if display_width(first_prefix) < width // 2:
                wrapped = wrap_text(
                    content[label_end + 2:],
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
    """Render scrollable shell output with a persistent right-hand mascot."""
    global _MASCOT_SESSION_ENABLED, _MASCOT_PLACEMENT_ACTIVE

    columns, rows = terminal_size()
    rows = max(rows, 1)
    uploaded_this_render = False
    refresh_succeeded = True

    mascot_fits = (
        columns >= MASCOT_MIN_TERMINAL_WIDTH
        and rows >= MASCOT_MIN_TERMINAL_HEIGHT
        and kitty_graphics_supported()
    )
    # Also initialize the image if Vulpnix started in a narrow terminal.
    if mascot_fits and not _MASCOT_SESSION_ENABLED:
        _MASCOT_SESSION_ENABLED = transmit_png(mascot_image_path(), sys.stdout)
        uploaded_this_render = _MASCOT_SESSION_ENABLED

    mascot_visible = _mascot_visible(columns, rows)

    # A resize or clear may invalidate the old placement or cached image.
    # Re-upload on the transition back to a visible layout.
    if (
        mascot_visible
        and _MASCOT_PLACEMENT_ACTIVE is False
        and not uploaded_this_render
    ):
        refresh_succeeded = transmit_png(mascot_image_path(), sys.stdout)

    visible_suggestions = suggestions[:max(rows - 2, 0)]
    page_height = max(rows - 1 - len(visible_suggestions), 0)
    display_lines = _fit_output_to_width(
        lines, columns, reserve_mascot=mascot_visible
    )
    visible_end = max(0, len(display_lines) - scroll_offset)
    visible_start = max(0, visible_end - page_height)
    visible_lines = display_lines[visible_start:visible_end]

    if selection is not None:
        highlighted_lines: list[str] = []
        for index, line in enumerate(visible_lines, start=visible_start):
            if _WELCOME_TABLE_MARKER_PREFIX in line:
                highlighted_lines.append(line)
                continue
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
    displayed_command = clip_ansi_line(
        command_line, max(columns - prompt_width, 0)
    )
    prompt_row = min(len(frame), rows - 1)
    frame.insert(prompt_row, prompt + displayed_command)
    frame.extend("" for _ in range(rows - len(frame) - len(visible_suggestions)))
    frame.extend(clip_ansi_line(line, columns) for line in visible_suggestions)

    welcome_border_rows: list[tuple[int, int]] = []
    output = ["\033[H"]
    for row_number, line in enumerate(frame[:rows]):
        if _WELCOME_TABLE_MARKER_PREFIX in line:
            marker_start = line.index(_WELCOME_TABLE_MARKER_PREFIX)
            marker_end = line.find(
                _WELCOME_TABLE_MARKER_END,
                marker_start + len(_WELCOME_TABLE_MARKER_PREFIX),
            )
            if marker_end >= 0:
                raw_width = line[
                    marker_start + len(_WELCOME_TABLE_MARKER_PREFIX):marker_end
                ]
                try:
                    table_width = int(raw_width)
                except ValueError:
                    table_width = 0

                line = (
                    line[:marker_start]
                    + line[marker_end + len(_WELCOME_TABLE_MARKER_END):]
                )
                right_column = len(_PRESENTATION_INDENT) + table_width - 1
                if table_width > 0 and 0 <= right_column < columns:
                    welcome_border_rows.append((row_number, right_column))

        output.extend((line, "\033[K"))
        if row_number < rows - 1:
            output.append("\r\n")

    # Draw only the fixed right edge. The text rows contain no trailing │.
    for row_number, right_column in welcome_border_rows:
        output.append(f"\033[{row_number + 1};{right_column + 1}H")
        output.append("│")

    if mascot_visible:
        image_column = _mascot_image_column(columns)
        frame_left = image_column - 2
        frame_width = MASCOT_COLUMNS + 4
        top_label = " ✦ VULPNIX ✦ "
        bottom_label = " LOOK CLOSER · STAY CURIOUS "
        tagline_row = _MASCOT_TOP_ROW + MASCOT_ROWS
        bottom_row = tagline_row + 1

        def mascot_border(label: str, first: str, last: str) -> str:
            available = max(0, frame_width - 2 - display_width(label))
            left_fill = available // 2
            right_fill = available - left_fill
            return (
                first
                + "─" * left_fill
                + label
                + "─" * right_fill
                + last
            )

        top_border = mascot_border(top_label, "╭", "╮")
        bottom_border = mascot_border(bottom_label, "╰", "╯")

        output.append(f"\033[1;{frame_left + 1}H")
        output.append(accent(top_border, bold=True))

        for row_number in range(2, bottom_row):
            output.append(f"\033[{row_number};{frame_left + 1}H")
            output.append(accent("│"))
            output.append(f"\033[{row_number};{frame_left + frame_width}H")
            output.append(accent("│"))

        output.append(f"\033[{bottom_row};{frame_left + 1}H")
        output.append(accent(bottom_border, bold=True))
        output.append(f"\033[{_MASCOT_TOP_ROW};{image_column + 1}H")
        output.append(
            placement_command(columns=MASCOT_COLUMNS, rows=MASCOT_ROWS)
        )
    elif _MASCOT_SESSION_ENABLED:
        output.append(delete_placement_command())

    prompt_column = min(prompt_width + cursor + 1, max(columns, 1))
    output.append(f"\033[{prompt_row + 1};{prompt_column}H")
    sys.stdout.write("".join(output))
    sys.stdout.flush()
    _MASCOT_PLACEMENT_ACTIVE = bool(
        mascot_visible and (uploaded_this_render or refresh_succeeded)
    )


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
    global _LIVE_PROGRESS, _MASCOT_SESSION_ENABLED, _MASCOT_PLACEMENT_ACTIVE
    _LIVE_PROGRESS = True
    _MASCOT_SESSION_ENABLED = False
    _MASCOT_PLACEMENT_ACTIVE = None
    output_lines: list[str] = []
    history: list[str] = []

    columns, rows = terminal_size()
    if (
        columns >= MASCOT_MIN_TERMINAL_WIDTH
        and rows >= MASCOT_MIN_TERMINAL_HEIGHT
        and kitty_graphics_supported()
    ):
        _MASCOT_SESSION_ENABLED = transmit_png(mascot_image_path(), sys.stdout)

    _, presentation = _capture_output(
        lambda: _show_presentation(
            kitty_mascot=_mascot_visible(columns, rows)
        )
    )
    _append_output(output_lines, presentation)

    def cleanup_mascot() -> None:
        global _MASCOT_SESSION_ENABLED
        if _MASCOT_SESSION_ENABLED:
            try:
                sys.stdout.write(delete_placement_command())
                sys.stdout.flush()
            except OSError:
                pass
        _MASCOT_SESSION_ENABLED = False

    with raw_input_mode():
        while True:
            try:
                command, _ = _read_command(output_lines, history, 0)
            except (EOFError, KeyboardInterrupt):
                _append_output(output_lines, "\nExiting Vulpnix.\n")
                _render_shell(output_lines, "", 0, 0)
                cleanup_mascot()
                _LIVE_PROGRESS = False
                return

            entered_command = color(
                command, _COMMAND_HIGHLIGHT_RGB, bold=True
            ) if command else ""
            entered = f"{accent('vulpnix>', bold=True)} {entered_command}"
            output_lines.append(entered)
            if command:
                history.append(command)

            keep_running, output = _capture_output(
                lambda: _dispatch_command(command)
            )
            _append_output(
                output_lines,
                output,
                title=_command_frame_title(command),
            )
            if not keep_running:
                _render_shell(output_lines, "", 0, 0)
                cleanup_mascot()
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
