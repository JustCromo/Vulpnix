"""Terminal-specific presentation helpers for the Vulpnix CLI."""

from contextlib import contextmanager
import signal
import sys
from collections.abc import Iterator


_ALT_SCREEN_ENTER = "\033[?1049h"
_ALT_SCREEN_EXIT = "\033[?1049l"
_RESET_STYLE = "\033[0m"


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
        sys.stdout.write(f"{_ALT_SCREEN_ENTER}\033[2J\033[H")
        sys.stdout.flush()
        yield
    finally:
        try:
            if transition_started:
                sys.stdout.write(_ALT_SCREEN_EXIT)
                sys.stdout.flush()
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
