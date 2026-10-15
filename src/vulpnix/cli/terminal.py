"""Terminal-specific presentation helpers for the Vulpnix CLI."""

from contextlib import contextmanager
import base64
from dataclasses import dataclass
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
_MOUSE_ON = "\033[?1002h\033[?1006h"
_MOUSE_OFF = "\033[?1006l\033[?1002l"
_RESET_STYLE = "\033[0m"
_ANSI_SEQUENCE = re.compile(r"\033\[[0-?]*[ -/]*[@-~]")


def color(text: str, rgb: tuple[int, int, int], *, bold: bool = False) -> str:
    """Apply true-color styling only when the terminal permits it."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    red, green, blue = rgb
    weight = "1;" if bold else ""
    return f"\033[{weight}38;2;{red};{green};{blue}m{text}{_RESET_STYLE}"

def accent(text: str, *, bold: bool = False) -> str:
    """Color Vulpnix branding orange when terminal colors are enabled."""
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
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
    """Read key events without terminal line buffering or echo."""
    file_descriptor = sys.stdin.fileno()
    previous_settings = termios.tcgetattr(file_descriptor)
    try:
        tty.setcbreak(file_descriptor)
        yield
    finally:
        termios.tcsetattr(file_descriptor, termios.TCSADRAIN, previous_settings)


def read_key(timeout: float | None = None) -> str | None:
    """Read one key, optionally returning after a timeout."""
    file_descriptor = sys.stdin.fileno()
    if timeout is not None and not select.select(
        [file_descriptor], [], [], timeout
    )[0]:
        return None

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



@dataclass(frozen=True, slots=True)
class MouseTextSelection:
    """Text selection using zero-based output-line and terminal-column positions."""

    anchor: tuple[int, int]
    focus: tuple[int, int]

    @property
    def bounds(self) -> tuple[tuple[int, int], tuple[int, int]]:
        """Return selection endpoints in reading order."""
        return tuple(sorted((self.anchor, self.focus)))

    def column_range(self, line: int) -> tuple[int, int | None] | None:
        """Return inclusive selected columns on a line; None means through line end."""
        start, end = self.bounds
        if line < start[0] or line > end[0]:
            return None

        first_column = start[1] if line == start[0] else 0
        last_column = end[1] if line == end[0] else None
        return first_column, last_column

    def contains(self, line: int, column: int) -> bool:
        """Return whether a terminal cell is included in this selection."""
        columns = self.column_range(line)
        if columns is None:
            return False
        first_column, last_column = columns
        return column >= first_column and (
            last_column is None or column <= last_column
        )


def _parse_sgr_mouse_event(
    sequence: str,
) -> tuple[int, int, int, bool] | None:
    """Parse an SGR mouse event as (button, x, y, released)."""
    match = re.fullmatch(
        r"\033\[<(\d+);(\d+);(\d+)([Mm])",
        sequence,
    )
    if match is None:
        return None

    button, x, y = (int(match.group(index)) for index in (1, 2, 3))
    if x < 1 or y < 1:
        return None

    return button, x, y, match.group(4) == "m"



def highlight_columns(text: str, start: int, end: int) -> str:
    """Render a zero-based, end-exclusive column range using reverse video."""
    plain = _ANSI_SEQUENCE.sub("", text)
    start = max(0, start)
    end = max(start, end)
    if end == start:
        return plain

    output: list[str] = []
    column = 0
    highlighted = False

    for character in plain:
        width = (
            0 if unicodedata.combining(character)
            else 2 if unicodedata.east_asian_width(character) in {"W", "F"}
            else 1
        )
        if width == 0:
            output.append(character)
            continue

        selected = column < end and column + width > start
        if selected != highlighted:
            output.append("\033[7m" if selected else "\033[27m")
            highlighted = selected
        output.append(character)
        column += width

    if highlighted:
        output.append("\033[27m")
    return "".join(output)



def copy_text_to_clipboard(text: str) -> bool:
    """Request a clipboard copy through the terminal's OSC 52 interface."""
    if not text or not sys.stdout.isatty():
        return False

    encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
    sys.stdout.write(f"\033]52;c;{encoded}\033\\")
    sys.stdout.flush()
    return True



def extract_selected_text(
    lines: list[str],
    selection: MouseTextSelection,
) -> str:
    """Extract selected visible text, preserving line breaks and Unicode width."""
    if selection.anchor == selection.focus:
        return ""

    start, end = selection.bounds
    if start[0] < 0 or end[0] >= len(lines):
        return ""

    selected_lines: list[str] = []
    for line_number in range(start[0], end[0] + 1):
        plain = _ANSI_SEQUENCE.sub("", lines[line_number])
        column_range = selection.column_range(line_number)
        if column_range is None:
            continue

        first_column, last_column = column_range
        end_column = (
            display_width(plain)
            if last_column is None
            else last_column + 1
        )

        selected_characters: list[str] = []
        column = 0
        previous_character_selected = False

        for character in plain:
            width = (
                0
                if unicodedata.combining(character)
                else 2
                if unicodedata.east_asian_width(character) in {"W", "F"}
                else 1
            )
            if width == 0:
                if previous_character_selected:
                    selected_characters.append(character)
                continue

            selected = (
                column < end_column
                and column + width > first_column
            )
            if selected:
                selected_characters.append(character)

            previous_character_selected = selected
            column += width

        selected_lines.append("".join(selected_characters))

    return "\n".join(selected_lines)


def terminal_size() -> tuple[int, int]:
    """Return terminal width and height, with a useful fallback."""
    size = shutil.get_terminal_size((80, 24))
    return size.columns, size.lines


def display_width(text: str) -> int:
    """Measure printable terminal cells, excluding ANSI control sequences."""
    visible = _ANSI_SEQUENCE.sub("", text)
    return sum(
        0
        if unicodedata.combining(character)
        else 2
        if unicodedata.east_asian_width(character) in {"W", "F"}
        else 1
        for character in visible
    )


def wrap_text(
    text: str,
    width: int,
    *,
    initial_indent: str = "",
    subsequent_indent: str | None = None,
) -> list[str]:
    """Wrap text by words to terminal-cell width, splitting only overlong tokens."""
    width = max(1, width)
    subsequent_indent = (
        initial_indent if subsequent_indent is None else subsequent_indent
    )

    def fit_indent(indent: str) -> str:
        fitted: list[str] = []
        columns = 0
        for character in indent:
            char_width = display_width(character)
            if columns + char_width >= width:
                break
            fitted.append(character)
            columns += char_width
        return "".join(fitted)

    first_indent = fit_indent(initial_indent)
    next_indent = fit_indent(subsequent_indent)

    def split_token(token: str, available: int) -> list[str]:
        pieces: list[str] = []
        piece = ""
        columns = 0
        for character in token:
            char_width = display_width(character)
            if piece and columns + char_width > available:
                pieces.append(piece)
                piece = ""
                columns = 0
            piece += character
            columns += char_width
        if piece:
            pieces.append(piece)
        return pieces

    lines: list[str] = []
    indent = first_indent
    line = indent
    line_has_text = False
    tokens = text.split()
    for token in tokens:
        available = max(width - display_width(next_indent), 1)
        pieces = split_token(token, available)
        for piece_index, piece in enumerate(pieces):
            continuation = piece_index > 0
            separator = " " if line_has_text and not continuation else ""
            if display_width(line + separator + piece) <= width:
                line += separator + piece
                line_has_text = True
                continue

            if line_has_text:
                lines.append(line)
            indent = next_indent
            line = indent + piece
            line_has_text = True

    if line_has_text or not lines:
        lines.append(line.rstrip())
    return lines


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
