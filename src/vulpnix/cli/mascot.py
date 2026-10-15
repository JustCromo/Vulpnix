"""Optional Kitty graphics protocol support for the Vulpnix mascot."""

import base64
import os
from pathlib import Path
import sys
from typing import TextIO

MASCOT_COLUMNS = 36
MASCOT_ROWS = 15
MASCOT_MIN_TERMINAL_WIDTH = 128
MASCOT_MIN_TERMINAL_HEIGHT = MASCOT_ROWS + 5
MASCOT_IMAGE_ID = (os.getpid() % 4_294_967_294) + 1
MASCOT_PLACEMENT_ID = 1
MASCOT_MARKER = "\x00VULPNIX_MASCOT_ANCHOR\x00"
_RAW_CHUNK_SIZE = 3072


def mascot_image_path() -> Path:
    """Return the PNG bundled alongside this module."""
    return Path(__file__).parent / "assets" / "vulpnix.png"


def kitty_graphics_supported(
    *,
    stdin=None,
    stdout=None,
    environ: dict[str, str] | None = None,
) -> bool:
    """Conservatively detect a Kitty terminal."""
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    environ = os.environ if environ is None else environ

    try:
        if not stdin.isatty() or not stdout.isatty():
            return False
    except (AttributeError, OSError):
        return False

    return bool(environ.get("KITTY_WINDOW_ID")) or (
        environ.get("TERM") == "xterm-kitty"
    )


def transmit_png(
    path: Path,
    stream: TextIO,
    *,
    image_id: int = MASCOT_IMAGE_ID,
    raw_chunk_size: int = _RAW_CHUNK_SIZE,
) -> bool:
    """Transmit a PNG to Kitty without displaying it."""
    if not 1 <= image_id <= 4_294_967_295:
        raise ValueError("image_id must be in the unsigned 32-bit positive range")
    if raw_chunk_size < 3:
        raise ValueError("raw_chunk_size must be at least 3 bytes")

    raw_chunk_size -= raw_chunk_size % 3

    try:
        data = path.read_bytes()
    except OSError:
        return False

    if not data:
        return False

    chunks = [
        base64.b64encode(data[offset:offset + raw_chunk_size]).decode("ascii")
        for offset in range(0, len(data), raw_chunk_size)
    ]

    try:
        for index, chunk in enumerate(chunks):
            more = int(index < len(chunks) - 1)
            if index == 0:
                metadata = f"a=t,i={image_id},f=100,q=2,m={more}"
            else:
                metadata = f"i={image_id},m={more}"
            stream.write(f"\x1b_G{metadata};{chunk}\x1b\\")
        stream.flush()
    except OSError:
        return False

    return True


def placement_command(
    *,
    image_id: int = MASCOT_IMAGE_ID,
    columns: int = MASCOT_COLUMNS,
    rows: int = MASCOT_ROWS,
    placement_id: int = MASCOT_PLACEMENT_ID,
) -> str:
    """Place or reposition the cached image."""
    if not 1 <= image_id <= 4_294_967_295:
        raise ValueError("image_id must be in the unsigned 32-bit positive range")
    if not 1 <= placement_id <= 4_294_967_295:
        raise ValueError("placement_id must be in the unsigned 32-bit positive range")
    if columns < 1 or rows < 1:
        raise ValueError("Image columns and rows must be positive")

    return (
        f"\x1b_Ga=p,i={image_id},p={placement_id},"
        f"c={columns},r={rows},C=1,q=2\x1b\\"
    )


def delete_placement_command(
    *,
    image_id: int = MASCOT_IMAGE_ID,
    placement_id: int = MASCOT_PLACEMENT_ID,
) -> str:
    """Remove this image placement without freeing its cached image data."""
    return f"\x1b_Ga=d,d=i,i={image_id},p={placement_id},q=2\x1b\\"
