"""Interactive command shell for Vulpnix."""

from collections.abc import Callable
from dataclasses import dataclass
import subprocess

from vulpnix.collectors import collect_services, collect_ssh_config, collect_system_info
from vulpnix.models import SSHConfig, Service, SystemInfo
from vulpnix import __version__
from vulpnix.cli.terminal import accent, alternate_screen, clear_screen


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
    print(f"  Root login:       {root_login}")
    print(f"  Password method:  {password_auth}")
    print("  Values are global sshd options; Match rules may vary by connection.")


def _ssh_error_message(error: Exception) -> str:
    if isinstance(error, FileNotFoundError):
        return "OpenSSH server (sshd) is not installed."
    if isinstance(error, subprocess.TimeoutExpired):
        return "sshd did not return configuration in time."
    if isinstance(error, subprocess.CalledProcessError):
        return "sshd could not validate its configuration or host keys."
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


def run_shell() -> None:
    """Run the interactive Vulpnix command shell."""
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
