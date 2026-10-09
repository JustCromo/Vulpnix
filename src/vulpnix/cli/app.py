"""Interactive command shell for Vulpnix."""

from collections.abc import Callable
from contextlib import redirect_stdout
from dataclasses import dataclass
import io
import subprocess
import sys

from vulpnix.collectors import (
    collect_local_users,
    collect_services,
    collect_ssh_config,
    collect_sudo_privileges,
    collect_system_info,
)
from vulpnix.collectors.ssh import SSHCommandError, SSHGUnsupportedError
from vulpnix.models import (
    SSHConfig,
    Service,
    SudoPrivilege,
    SudoPrivilegeStatus,
    SystemInfo,
    User,
)
from vulpnix import __version__
from vulpnix.findings import Finding
from vulpnix.cli.terminal import (
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
from vulpnix.rules import (
    check_ssh_empty_passwords,
    check_ssh_password_authentication,
    check_ssh_public_key_authentication,
    check_ssh_root_login,
    verified_privileged_accounts,
)


_FOX_ART = (
    "⠀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⣸⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⢠⡟⠘⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⢰⡟⠀⠀⠈⠻⣷⣤⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⣠⡟⠀⠀⠀⠀⠀⠈⢻⡿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⣰⡟⠀⠀⠀⠀⠀⠀⠀⠀⠻⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣇⠀⣠⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀",
    "⣾⡁⢀⣠⠴⠒⠲⣤⣠⠶⠋⠳⣤⣸⣿⣰⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀",
    "⣿⠟⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⣽⠏⣿⡿⢿⣿⣿⣿⣷⣄⠀⠀⠀⠀⢠⣾⣿⣿⣿⠋⢹⡇⠀⠀⠀⠀⠀⠀",
    "⢹⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡟⠀⣿⠁⠀⠙⣿⡛⠛⢿⡶⠶⠶⠶⣿⣄⣀⣰⠃⠀⢸⡇⠀⠀⠀⠀⠀⠀",
    "⠈⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⢰⡿⠁⠀⣿⠀⠀⠀⠈⢷⡀⠘⠛⠀⠀⠀⠀⠈⠉⠳⣄⠀⢸⡇⠀⠀⠀⠀⠀⠀",
    "⠀⠈⢿⣦⡀⠀⠀⠀⠀⠀⢀⣿⣇⣀⠀⢻⠀⠀⠀⠀⢰⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣾⠃⠀⣤⣤⣄⠀⠀",
    "⠀⠀⠀⠉⠻⢶⣄⣠⣴⠞⠛⠉⠉⠙⠻⢾⣇⠀⢀⣰⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡄⠀⣿⢩⡿⣿⡆",
    "⠀⠀⠀⠀⣠⣴⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⢹⡷⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⣿⣟⣵⡿⠁",
    "⠀⢀⣠⡾⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣇⠀⠀⠀⣴⣿⠀⠀⠀⠀⠀⠀⢠⣶⠀⠀⣸⡇⠀⠙⠋⠁⠀⠀",
    "⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣄⣈⣀⣙⣁⠀⠀⣶⣾⡶⠀⠻⠿⠀⢠⣿⣁⡀⠀⠀⠀⠀⠀",
    "⠈⠛⠻⠿⠶⠶⠶⡤⣤⣤⣤⣄⣀⣤⣀⣠⣤⣀⣀⣹⣿⣿⣿⣿⣤⣽⣿⣴⣶⣶⡦⢼⣿⣿⣿⣿⠇⠀⠀⠀⠀",
)
_PRESENTATION_INDENT = "    "
_TITLE_BOX_WIDTH = 34
_OUTPUT_LAYOUT_CACHE: tuple[int, int, int, str, list[str]] | None = None
_SECTION_WIDTH = 48


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
                    print("  scan host  Host facts only")
                    print("  scan users  User and privilege assessment")
                    print("  scan users --details  Include the complete account inventory")
                    print("  scan service  Services and startup state")
                    print("  scan ssh  SSH assessment only")


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
    print("Interactive CLI foundation; host assessment is not implemented yet.")


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


def _show_system_info(info: SystemInfo, title: str = "SYSTEM") -> None:
    distribution = _display_value(info.distribution)
    if info.distribution_version:
        distribution += f" ({_display_value(info.distribution_version)})"

    _section(title)
    print(f"  {'Host':<16} {_display_value(info.hostname)}")
    print(f"  {'Distribution':<16} {distribution}")
    print(f"  {'Kernel':<16} {_display_value(info.kernel_release)}")
    print(f"  {'Architecture':<16} {_display_value(info.architecture)}")
    print(f"  {'Uptime':<16} {_format_uptime(info.uptime_seconds)}")


def _show_host_assessment(title: str = "SYSTEM") -> bool:
    """Collect and show host facts, returning whether collection succeeded."""
    try:
        system_info = collect_system_info()
    except NotImplementedError:
        _section(title)
        print("Host facts are supported on Linux only.")
        return False

    _show_system_info(system_info, title)
    return True


def _show_services(services: tuple[Service, ...]) -> None:
    active = sum(service.state == "active" for service in services)
    inactive = sum(service.state == "inactive" for service in services)
    other_state = len(services) - active - inactive
    enabled = sum(service.enabled is True for service in services)
    disabled = sum(service.enabled is False for service in services)
    unknown_enabled = len(services) - enabled - disabled

    _section("SERVICES")
    print(f"  {'Units':<16} {len(services)}")
    print(
        f"  {'State':<16} {active} active · {inactive} inactive · "
        f"{other_state} other/unknown"
    )
    print(
        f"  {'Startup enabled':<16} {enabled} yes · {disabled} no · "
        f"{unknown_enabled} unknown"
    )

    review_services = tuple(
        service
        for service in services
        if service.state == "active" and service.unit_file_state == "enabled"
    )
    print(f"\n{accent('ACTIVE AT STARTUP', bold=True)}")
    if not review_services:
        print("  No active, startup-enabled services found.")
        return

    print("  Active now and enabled to start at boot:")
    for service in review_services:
        print(f"  • {_display_value(service.name)}")


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


def _show_users_assessment(*, detailed: bool = False) -> None:
    """Render a concise account assessment or opt-in full inventory."""
    try:
        users = collect_local_users()
        sudo_privileges = collect_sudo_privileges(users)
        section = _user_report_section(
            users, sudo_privileges, detailed=detailed
        )
    except (OSError, UnicodeError, ValueError) as error:
        section = ReportSection(
            title="USERS",
            status="Unavailable / NOT_ASSESSED",
            message=_user_error_message(error),
        )
    print("\n".join(render_report_section(section, terminal_size()[0])))


def _show_service_assessment() -> None:
    """Collect systemd service state and startup information."""
    try:
        services = collect_services()
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        _section("SERVICES")
        print(f"  Unavailable: {_service_error_message(error)}")
    else:
        _show_services(services)


def _show_ssh_config(config: SSHConfig) -> None:
    _section("SSH")
    print(f"  {accent('GLOBAL LOGIN OPTIONS', bold=True)}")
    root_login = {
        "yes": "yes",
        "no": "no",
        "prohibit-password": "key login only",
        "forced-commands-only": "restricted key login only",
    }[config.permit_root_login]
    password_auth = "yes" if config.password_authentication else "no"
    empty_passwords = "yes" if config.permit_empty_passwords else "no"
    public_key_auth = "yes" if config.public_key_authentication else "no"
    print(f"  {'Option':<27} Value")
    print(f"  {'─' * 27} {'─' * 10}")
    print(f"  {'Root login':<27} {root_login}")
    print(f"  {'Password authentication':<27} {password_auth}")
    print(f"  {'Public-key authentication':<27} {public_key_auth}")
    print(f"  {'Permit empty passwords':<27} {empty_passwords}")
    print("  Values are global sshd options; Match rules may vary by connection.")


def _show_findings(findings: tuple[Finding, ...]) -> int:
    _section("FINDINGS")
    if not findings:
        print("  No SSH findings.")
        return 0

    for finding in findings:
        print(f"\n  [REVIEW] {finding.title}")
        print(f"  Rule:           {finding.rule_id}")
        print(f"  Evidence:       {finding.evidence}")
        print("  Why it matters:")
        print(f"    {finding.explanation}")
        print("  Recommendation:")
        print(f"    {finding.recommendation}")
    return len(findings)


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


def _show_ssh_assessment() -> int:
    """Collect global SSH options and display their current findings."""
    try:
        ssh_config = collect_ssh_config()
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        _section("SSH")
        print(f"  {accent('GLOBAL LOGIN OPTIONS', bold=True)}")
        status = (
            "NOT ASSESSED / Unavailable"
            if isinstance(error, SSHGUnsupportedError)
            else "Unavailable"
        )
        print(f"  {status}: {_ssh_error_message(error)}")
        return 0

    _show_ssh_config(ssh_config)
    findings = _ssh_findings(ssh_config)
    return _show_findings(findings)


def _ssh_findings(ssh_config: SSHConfig) -> tuple[Finding, ...]:
    """Run the existing SSH checks and return their findings unchanged."""
    return (
        *check_ssh_root_login(ssh_config),
        *check_ssh_password_authentication(ssh_config),
        *check_ssh_empty_passwords(ssh_config),
        *check_ssh_public_key_authentication(ssh_config),
    )


def _service_report_section(services: tuple[Service, ...]) -> ReportSection:
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
    if startup_services:
        items = startup_services
    else:
        items = ("No active, startup-enabled services found.",)
    return ReportSection(
        title="SERVICES",
        facts=(
            ("Units", str(len(services))),
            ("State", f"{active} active · {inactive} inactive · {other_state} other/unknown"),
            ("Startup enabled", f"{enabled} yes · {disabled} no · {unknown_enabled} unknown"),
        ),
        items=items,
        items_label=(
            "Active now and enabled to start at boot:" if startup_services else None
        ),
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


def _show_scan() -> None:
    """Collect existing assessment data and render a structured report."""
    try:
        system_info = collect_system_info()
    except NotImplementedError:
        report = ScanReport(
            host=None,
            host_message="Host facts are supported on Linux only.",
            sections=(),
            findings=(),
            scope=("system facts", "users", "services", "SSH configuration"),
        )
        print("\n".join(render_scan_report(report, terminal_size()[0])))
        return

    service_section: ReportSection
    try:
        services = collect_services()
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        service_section = ReportSection(
            title="SERVICES",
            message=_service_error_message(error),
            status="Unavailable",
        )
    else:
        service_section = _service_report_section(services)

    try:
        users = collect_local_users()
        sudo_privileges = collect_sudo_privileges(users)
        user_section = _user_report_section(users, sudo_privileges)
    except (OSError, UnicodeError, ValueError) as error:
        user_section = ReportSection(
            title="USERS",
            message=_user_error_message(error),
            status="Unavailable / NOT_ASSESSED",
        )

    findings: tuple[Finding, ...] = ()
    ssh_section: ReportSection
    try:
        ssh_config = collect_ssh_config()
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        status = (
            "NOT ASSESSED / Unavailable"
            if isinstance(error, SSHGUnsupportedError)
            else "Unavailable"
        )
        ssh_section = ReportSection(
            title="SSH",
            status=status,
            message=_ssh_error_message(error),
        )
    else:
        ssh_section = _ssh_report_section(ssh_config)
        findings = _ssh_findings(ssh_config)

    report = ScanReport(
        host=system_info,
        sections=(user_section, service_section, ssh_section),
        findings=findings,
        scope=("system facts", "users", "services", "SSH configuration"),
    )
    print("\n".join(render_scan_report(report, terminal_size()[0])))


def _show_presentation() -> None:
    """Render the initial Vulpnix screen."""
    top = "╭" + "─" * _TITLE_BOX_WIDTH + "╮"
    bottom = "╰" + "─" * _TITLE_BOX_WIDTH + "╯"
    print(_PRESENTATION_INDENT + accent(top))
    for label, bold in (("VULPNIX", True), ("Linux host risk assessment", False)):
        padding = " " * (_TITLE_BOX_WIDTH - len(label) - 2)
        line = "│ " + label + padding + " │"
        print(_PRESENTATION_INDENT + accent(line, bold=bold))
    print(_PRESENTATION_INDENT + accent(bottom))
    print()

    for row in _FOX_ART:
        print(_PRESENTATION_INDENT + accent(row))


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
    "scan host",
    "scan users",
    "scan users --details",
    "scan service",
    "scan ssh",
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
        if parts == ["scan", "host"]:
            _show_host_assessment("HOST DETAILS")
            return True
        if parts in (["scan", "users"], ["scan", "users", "--details"]):
            detailed = len(parts) == 3
            _show_users_assessment(detailed=detailed)
            return True
        if parts == ["scan", "service"]:
            _show_service_assessment()
            return True
        if parts == ["scan", "ssh"]:
            _show_ssh_assessment()
            return True
        if len(parts) > 1:
            print("Usage: scan [host|users [--details]|service|ssh]")
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


def _render_shell(
    lines: list[str],
    command_line: str,
    cursor: int,
    scroll_offset: int,
    suggestions: tuple[str, ...] = (),
) -> None:
    columns, rows = terminal_size()
    rows = max(rows, 1)
    visible_suggestions = suggestions[: max(rows - 2, 0)]
    page_height = max(rows - 1 - len(visible_suggestions), 0)
    display_lines = _fit_output_to_width(lines, columns)
    visible_end = max(0, len(display_lines) - scroll_offset)
    visible_start = max(0, visible_end - page_height)
    visible_lines = display_lines[visible_start:visible_end]

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

    while True:
        _render_shell(
            lines, command_line, cursor, scroll_offset, completion_suggestions
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
        if key.startswith("\033[<"):
            try:
                button = int(key[3:].split(";", maxsplit=1)[0])
            except ValueError:
                continue
            if button & 64:
                columns, rows = terminal_size()
                page_height = max(rows - 1, 1)
                max_offset = max(
                    0, len(_fit_output_to_width(lines, columns)) - page_height
                )
                direction = 1 if button & 1 == 0 else -1
                scroll_offset = min(max_offset, max(0, scroll_offset + direction))
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
                return

            entered = f"{accent('vulpnix>', bold=True)} {command}"
            output_lines.append(entered)
            if command:
                history.append(command)

            keep_running, output = _capture_output(lambda: _dispatch_command(command))
            _append_output(output_lines, output)
            if not keep_running:
                _render_shell(output_lines, "", 0, 0)
                return


def run_shell() -> None:
    """Run Vulpnix with mouse-wheel scrolling in an interactive terminal."""
    if sys.stdin.isatty() and sys.stdout.isatty():
        _run_interactive_shell()
        return

    _show_presentation()
    while True:
        try:
            command = input(f"{accent('vulpnix>', bold=True)} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting Vulpnix.")
            return
        if not _dispatch_command(command):
            return


def main() -> None:
    """Start the Vulpnix shell."""
    with alternate_screen():
        run_shell()
