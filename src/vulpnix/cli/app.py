"""Interactive command shell for Vulpnix."""

from collections.abc import Callable
from contextlib import redirect_stdout
from dataclasses import dataclass
import io
import subprocess
import sys

from vulpnix.collectors import collect_services, collect_ssh_config, collect_system_info
from vulpnix.models import SSHConfig, Service, SystemInfo
from vulpnix import __version__
from vulpnix.findings import Finding
from vulpnix.cli.terminal import (
    accent,
    alternate_screen,
    clip_ansi_line,
    clear_screen,
    raw_input_mode,
    read_key,
    terminal_size,
)
from vulpnix.rules import check_ssh_empty_passwords, check_ssh_root_login


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


def _show_system_info(info: SystemInfo) -> None:
    distribution = _display_value(info.distribution)
    if info.distribution_version:
        distribution += f" ({_display_value(info.distribution_version)})"

    print(f"\n{accent('HOST FACTS')}")
    print(f"  Host:         {_display_value(info.hostname)}")
    print(f"  Distribution: {distribution}")
    print(f"  Kernel:       {_display_value(info.kernel_release)}")
    print(f"  Architecture: {_display_value(info.architecture)}")
    print(f"  Uptime:       {_format_uptime(info.uptime_seconds)}")


def _show_services(services: tuple[Service, ...]) -> None:
    active = sum(service.state == "active" for service in services)
    inactive = sum(service.state == "inactive" for service in services)
    other_state = len(services) - active - inactive
    enabled = sum(service.enabled is True for service in services)
    disabled = sum(service.enabled is False for service in services)
    unknown_enabled = len(services) - enabled - disabled

    print(f"\n{accent('SYSTEMD SERVICES')}")
    print(f"  Units:   {len(services)}")
    print(f"  State:   {active} active · {inactive} inactive · {other_state} other/unknown")
    print(f"  Enabled: {enabled} yes · {disabled} no · {unknown_enabled} unknown")

    review_services = tuple(
        service
        for service in services
        if service.state == "active" and service.unit_file_state == "enabled"
    )
    print(f"\n{accent('ACTIVE AT STARTUP')}")
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


def _show_ssh_config(config: SSHConfig) -> None:
    print(f"\n{accent('SSH LOGIN OPTIONS')}")
    root_login = {
        "yes": "yes",
        "no": "no",
        "prohibit-password": "key login only",
        "forced-commands-only": "restricted key login only",
    }[config.permit_root_login]
    password_auth = "yes" if config.password_authentication else "no"
    empty_passwords = "yes" if config.permit_empty_passwords else "no"
    print(f"  Root login:       {root_login}")
    print(f"  Password method:  {password_auth}")
    print(f"  Empty passwords:  {empty_passwords}")
    print("  Values are global sshd options; Match rules may vary by connection.")


def _show_findings(findings: tuple[Finding, ...]) -> None:
    print(f"\n{accent('FINDINGS')}")
    if not findings:
        print("  No SSH root-login finding.")
        return

    for finding in findings:
        print(f"  [REVIEW] {finding.title}")
        print(f"  Rule:           {finding.rule_id}")
        print(f"  Evidence:       {finding.evidence}")
        print(f"  Why it matters: {finding.explanation}")
        print(f"  Suggested step: {finding.recommendation}")


def _ssh_error_message(error: Exception) -> str:
    if isinstance(error, FileNotFoundError):
        return "OpenSSH server (sshd) is not installed."
    if isinstance(error, subprocess.TimeoutExpired):
        return "sshd did not return configuration in time."
    if isinstance(error, subprocess.CalledProcessError):
        return "sshd -G could not print the effective configuration."
    if isinstance(error, (UnicodeError, ValueError)):
        return "sshd returned unreadable configuration data."
    return "SSH configuration is unavailable."


def _show_scan() -> None:
    """Collect host facts and identify active services enabled at boot."""
    print(f"\n{accent('HOST INVENTORY')}")
    try:
        system_info = collect_system_info()
    except NotImplementedError:
        print("Host facts are supported on Linux only.")
        return

    _show_system_info(system_info)

    try:
        services = collect_services()
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        print(f"\n{accent('SYSTEMD SERVICES')}")
        print(f"  Unavailable: {_service_error_message(error)}")
    else:
        _show_services(services)

    try:
        ssh_config = collect_ssh_config()
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as error:
        print(f"\n{accent('SSH LOGIN OPTIONS')}")
        print(f"  Unavailable: {_ssh_error_message(error)}")
    else:
        _show_ssh_config(ssh_config)
        findings = (
            *check_ssh_root_login(ssh_config),
            *check_ssh_empty_passwords(ssh_config),
        )
        _show_findings(findings)

    print("\nThese are configuration facts, not a complete access test or risk score.")


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
    Command("scan", "ASSESSMENT", "Collect host facts", _show_scan),
    Command("clear", "SESSION", "Refresh screen", _clear_screen),
    Command("exit", "SESSION", "Quit", None),
)
_COMMANDS_BY_NAME = {command.name: command for command in _COMMANDS}


def _dispatch_command(command_name: str) -> bool:
    """Dispatch one known command; return False when the shell should exit."""
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
    clear_sequence = "\033[2J\033[H"
    if clear_sequence in output:
        lines.clear()
        output = output.replace(clear_sequence, "")
    if output:
        lines.extend(output.splitlines())


def _render_shell(
    lines: list[str], command_line: str, cursor: int, scroll_offset: int
) -> None:
    columns, rows = terminal_size()
    rows = max(rows, 1)
    page_height = max(rows - 1, 0)
    visible_end = max(0, len(lines) - scroll_offset)
    visible_start = max(0, visible_end - page_height)
    visible_lines = lines[visible_start:visible_end]

    prompt = f"{accent('vulpnix>', bold=True)} "
    frame = [clip_ansi_line(line, columns) for line in visible_lines]
    prompt_row = min(len(frame), rows - 1)
    frame.insert(prompt_row, prompt + command_line)
    frame.extend("" for _ in range(rows - len(frame)))

    output = ["\033[H"]
    for row_number, line in enumerate(frame[:rows]):
        output.extend((line, "\033[K"))
        if row_number < rows - 1:
            output.append("\r\n")

    prompt_column = len("vulpnix> ") + cursor + 1
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

    while True:
        _render_shell(lines, command_line, cursor, scroll_offset)
        key = read_key()

        if key.startswith("\033[<"):
            try:
                button = int(key[3:].split(";", maxsplit=1)[0])
            except ValueError:
                continue
            if button & 64:
                columns, rows = terminal_size()
                page_height = max(rows - 1, 1)
                max_offset = max(0, len(lines) - page_height)
                direction = 1 if button & 1 == 0 else -1
                scroll_offset = min(max_offset, max(0, scroll_offset + direction * 3))
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
