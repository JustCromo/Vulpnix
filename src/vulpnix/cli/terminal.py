"""Terminal-specific presentation helpers for the Vulpnix CLI."""

from contextlib import contextmanager
import os
import re
import select
import shutil
import signal
import sys
import termios
import tty
import unicodedata
from collections.abc import Iterator


_ALT_SCREEN_ENTER = "\033[?1049h"
_ALT_SCREEN_EXIT = "\033[?1049l"
_MOUSE_ON = "\033[?1000h\033[?1006h"
_MOUSE_OFF = "\033[?1006l\033[?1000l"
_RESET_STYLE = "\033[0m"
_ANSI_SEQUENCE = re.compile(r"\033\[[0-?]*[ -/]*[@-~]")


def color(text: str, rgb: tuple[int, int, int], *, bold: bool = False) -> str:
    """Apply a true-color foreground style when attached to a terminal."""
    if not sys.stdout.isatty():
        return text
    red, green, blue = rgb
    weight = "1;" if bold else ""
    return f"\033[{weight}38;2;{red};{green};{blue}m{text}{_RESET_STYLE}"


def accent(text: str, *, bold: bool = False) -> str:
    """Color branding with Vulpnix orange when attached to a terminal."""
    if not sys.stdout.isatty():
        return text
    weight = "1;" if bold else ""
    return f"\033[{weight}38;2;255;179;71m{text}{_RESET_STYLE}"


def clear_screen() -> None:
    """Clear the visible terminal screen when running interactively."""
    if not sys.stdout.isatty():
        print("Clear is available in an interactive terminal.")
        return
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


@contextmanager
def raw_input_mode() -> Iterator[None]:
    """Read key and mouse events without terminal line buffering or echo."""
    file_descriptor = sys.stdin.fileno()
    previous_settings = termios.tcgetattr(file_descriptor)
    try:
        tty.setcbreak(file_descriptor)
        yield
    finally:
        termios.tcsetattr(file_descriptor, termios.TCSADRAIN, previous_settings)


def read_key() -> str:
    """Read one key, preserving escape sequences used for keys and mouse."""
    file_descriptor = sys.stdin.fileno()
    character = os.read(file_descriptor, 1).decode("utf-8", errors="replace")
    if character != "\033":
        return character

    sequence = character
    while select.select([file_descriptor], [], [], 0.04)[0]:
        character = os.read(file_descriptor, 1).decode("utf-8", errors="replace")
        sequence += character
        if len(sequence) > 2 and "@" <= character <= "~":
            break
    return sequence


def terminal_size() -> tuple[int, int]:
    """Return terminal width and height, with a useful fallback."""
    size = shutil.get_terminal_size((80, 24))
    return size.columns, size.lines


def clip_ansi_line(line: str, width: int) -> str:
    """Clip a line to terminal width while preserving ANSI styling sequences."""
    clipped: list[str] = []
    column = 0
    position = 0
    for match in _ANSI_SEQUENCE.finditer(line):
        text = line[position:match.start()]
        for character in text:
            character_width = 0 if unicodedata.combining(character) else (
                2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
            )
            if column + character_width > width:
                clipped.append(_RESET_STYLE)
                return "".join(clipped)
            clipped.append(character)
            column += character_width
        clipped.append(match.group())
        position = match.end()

    for character in line[position:]:
        character_width = 0 if unicodedata.combining(character) else (
            2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
        )
        if column + character_width > width:
            clipped.append(_RESET_STYLE)
            return "".join(clipped)
        clipped.append(character)
        column += character_width
    return "".join(clipped)


def _exit_on_signal(signum: int, _frame: object) -> None:
    """Turn termination signals into normal Python unwinding."""
    raise SystemExit(128 + signum)


@contextmanager
def alternate_screen() -> Iterator[None]:
    """Use and reliably leave the terminal's alternate screen buffer."""
    if not sys.stdout.isatty():
        yield
        return

    signals = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)
    previous_handlers: dict[signal.Signals, signal.Handlers] = {}
    transition_started = False

    try:
        for signum in signals:
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, _exit_on_signal)

        transition_started = True
        sys.stdout.write(f"{_ALT_SCREEN_ENTER}{_MOUSE_ON}\033[2J\033[H")
        sys.stdout.flush()
        yield
    finally:
        try:
            if transition_started:
                sys.stdout.write(f"{_MOUSE_OFF}{_ALT_SCREEN_EXIT}")
                sys.stdout.flush()
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
