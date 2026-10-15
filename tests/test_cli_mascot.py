"""Tests for the Kitty mascot and Vulpnix presentation."""

import base64
import io
from contextlib import redirect_stdout
from pathlib import Path
import re
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix.cli.terminal import display_width
from vulpnix.cli.mascot import (
    MASCOT_MARKER,
    delete_placement_command,
    kitty_graphics_supported,
    mascot_image_path,
    placement_command,
    transmit_png,
)


_TEST_INDENT = "    "


class TTYBuffer(io.StringIO):
    def isatty(self):
        return True


class KittyGraphicsTests(unittest.TestCase):
    def test_detects_kitty_terminal(self):
        tty = TTYBuffer()
        self.assertTrue(
            kitty_graphics_supported(
                stdin=tty,
                stdout=tty,
                environ={"TERM": "xterm-kitty"},
            )
        )

    def test_detects_kitty_window_id(self):
        tty = TTYBuffer()
        self.assertTrue(
            kitty_graphics_supported(
                stdin=tty,
                stdout=tty,
                environ={"KITTY_WINDOW_ID": "42"},
            )
        )

    def test_rejects_non_tty_or_other_terminal(self):
        tty = TTYBuffer()
        self.assertFalse(
            kitty_graphics_supported(
                stdin=io.StringIO(),
                stdout=tty,
                environ={"TERM": "xterm-kitty"},
            )
        )
        self.assertFalse(
            kitty_graphics_supported(
                stdin=tty,
                stdout=tty,
                environ={"TERM": "xterm-256color"},
            )
        )

    def test_transmits_png_as_reconstructable_base64_chunks(self):
        data = bytes(index % 256 for index in range(10_000))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mascot.png"
            path.write_bytes(data)
            output = io.StringIO()

            self.assertTrue(
                transmit_png(path, output, image_id=12345, raw_chunk_size=3072)
            )

        terminator = re.escape("\x1b\\")
        commands = re.findall(
            r"\x1b_G([^;]*);([A-Za-z0-9+/=]*)" + terminator,
            output.getvalue(),
        )

        self.assertGreater(len(commands), 1)
        self.assertIn("a=t", commands[0][0])
        self.assertIn("i=12345", commands[0][0])
        self.assertIn("f=100", commands[0][0])
        self.assertIn("m=1", commands[0][0])
        self.assertIn("m=0", commands[-1][0])

        decoded = b"".join(
            base64.b64decode(payload) for _, payload in commands
        )
        self.assertEqual(decoded, data)

    def test_missing_png_returns_false(self):
        self.assertFalse(
            transmit_png(Path("/no/such/mascot.png"), io.StringIO())
        )

    def test_placement_command_has_requested_size(self):
        command = placement_command(image_id=12345, columns=36, rows=15)
        self.assertIn("a=p", command)
        self.assertIn("i=12345", command)
        self.assertIn("c=36", command)
        self.assertIn("r=15", command)


class MascotShellIntegrationTests(unittest.TestCase):
    def test_packaged_mascot_png_exists(self):
        path = mascot_image_path()
        self.assertTrue(path.is_file())
        self.assertTrue(path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n"))

    def test_welcome_content_is_short_and_actionable(self):
        output = io.StringIO()
        context = SimpleNamespace(mode="ROOTLESS", uid=1000, privileged=False)
        with (
            patch.object(app, "terminal_size", return_value=(175, 45)),
            patch.object(app, "current_privilege_context", return_value=context),
            redirect_stdout(output),
        ):
            app._show_presentation(kitty_mascot=True)

        rendered = output.getvalue()
        for expected in (
            "VULPNIX · LINUX HOST SECURITY",
            "ABOUT",
            "QUICK START",
            "SESSION",
            "╰",
            "Explore available commands and options",
            "Run a full Linux host assessment",
            "ROOTLESS",
        ):
            self.assertIn(expected, rendered)

        content_rows = [
            line for line in rendered.splitlines()
            if "Evidence-based security assessment" in line
            or "Explore available commands and options" in line
            or "Run a full Linux host assessment" in line
        ]
        self.assertTrue(content_rows)
        for line in content_rows:
            self.assertIn("│ ", line)
            self.assertIn(app._WELCOME_TABLE_MARKER_PREFIX, line)
            before_marker = line.split(app._WELCOME_TABLE_MARKER_PREFIX, 1)[0]
            self.assertFalse(before_marker.rstrip().endswith("│"))


    def test_report_text_reserves_right_hand_mascot_area(self):
        long_text = "Long report evidence " * 12
        with (
            patch.object(app, "_MASCOT_SESSION_ENABLED", True),
            patch.object(app, "kitty_graphics_supported", return_value=True),
            patch.object(app, "terminal_size", return_value=(175, 45)),
        ):
            app._OUTPUT_LAYOUT_CACHE = None
            fitted = app._fit_output_to_width(
                [long_text], 175, reserve_mascot=True
            )

        self.assertTrue(
            all(display_width(line) <= app._mascot_content_width(175) for line in fitted)
        )
        self.assertIn("Long report evidence", " ".join(fitted))

    def test_mascot_and_title_stay_visible_during_scan_output(self):
        output = io.StringIO()
        app._OUTPUT_LAYOUT_CACHE = None
        with (
            patch.object(app, "terminal_size", return_value=(175, 45)),
            patch.object(app, "_MASCOT_SESSION_ENABLED", True),
            patch.object(app, "kitty_graphics_supported", return_value=True),
            redirect_stdout(output),
        ):
            app._render_shell(["scan report: " + "evidence " * 30], "", 0, 0)

        rendered = output.getvalue()
        image_column = app._mascot_image_column(175)
        frame_left = image_column - 2
        frame_width = app.MASCOT_COLUMNS + 4
        top_label = " ✦ VULPNIX ✦ "
        bottom_label = " LOOK CLOSER · STAY CURIOUS "

        def expected_border(label, first, last):
            available = frame_width - 2 - display_width(label)
            left_fill = available // 2
            right_fill = available - left_fill
            return first + "─" * left_fill + label + "─" * right_fill + last

        self.assertIn(expected_border(top_label, "╭", "╮"), rendered)
        self.assertIn(expected_border(bottom_label, "╰", "╯"), rendered)
        self.assertIn(
            f"\x1b[{app._MASCOT_TOP_ROW};{image_column + 1}H",
            rendered,
        )
        self.assertIn(placement_command(), rendered)
        self.assertNotIn(delete_placement_command(), rendered)

    def test_table_right_border_is_drawn_at_fixed_column(self):
        output = io.StringIO()
        app._OUTPUT_LAYOUT_CACHE = None
        marker = f"{app._WELCOME_TABLE_MARKER_PREFIX}96{app._WELCOME_TABLE_MARKER_END}"
        row = "    │ Example text                                             " + marker

        with (
            patch.object(app, "terminal_size", return_value=(175, 45)),
            patch.object(app, "_MASCOT_SESSION_ENABLED", True),
            patch.object(app, "kitty_graphics_supported", return_value=True),
            redirect_stdout(output),
        ):
            app._render_shell([row], "", 0, 0)

        rendered = output.getvalue()
        self.assertIn("\x1b[1;100H│", rendered)
        self.assertNotIn(marker, rendered)


    def test_narrow_terminal_hides_mascot_without_clipping_report(self):
        output = io.StringIO()
        app._OUTPUT_LAYOUT_CACHE = None
        with (
            patch.object(app, "terminal_size", return_value=(100, 40)),
            patch.object(app, "_MASCOT_SESSION_ENABLED", True),
            patch.object(app, "kitty_graphics_supported", return_value=True),
            redirect_stdout(output),
        ):
            app._render_shell(["full width fallback report"], "", 0, 0)

        rendered = output.getvalue()
        self.assertIn(delete_placement_command(), rendered)
        self.assertNotIn(placement_command(), rendered)
        self.assertIn("full width fallback report", rendered)

    def test_mascot_is_reuploaded_when_wide_layout_returns(self):
        output = io.StringIO()
        app._OUTPUT_LAYOUT_CACHE = None

        with (
            patch.object(
                app, "terminal_size",
                side_effect=[(100, 40), (175, 45)],
            ),
            patch.object(app, "_MASCOT_SESSION_ENABLED", True),
            patch.object(app, "_MASCOT_PLACEMENT_ACTIVE", True),
            patch.object(app, "kitty_graphics_supported", return_value=True),
            patch.object(app, "transmit_png", return_value=True) as upload,
            redirect_stdout(output),
        ):
            app._render_shell(["narrow layout"], "", 0, 0)
            app._render_shell(["wide layout"], "", 0, 0)

        upload.assert_called_once()
        rendered = output.getvalue()
        self.assertIn(delete_placement_command(), rendered)
        self.assertIn(placement_command(), rendered)

    def test_starting_narrow_loads_mascot_after_resize(self):
        output = io.StringIO()
        app._OUTPUT_LAYOUT_CACHE = None

        with (
            patch.object(
                app, "terminal_size",
                side_effect=[(100, 40), (175, 45)],
            ),
            patch.object(app, "_MASCOT_SESSION_ENABLED", False),
            patch.object(app, "_MASCOT_PLACEMENT_ACTIVE", None),
            patch.object(app, "kitty_graphics_supported", return_value=True),
            patch.object(app, "transmit_png", return_value=True) as upload,
            redirect_stdout(output),
        ):
            app._render_shell(["initial narrow layout"], "", 0, 0)
            app._render_shell(["resized wide layout"], "", 0, 0)

        upload.assert_called_once()
        self.assertIn(placement_command(), output.getvalue())

    def test_clear_restores_the_persistent_mascot_layout(self):
        with (
            patch.object(app, "_MASCOT_SESSION_ENABLED", True),
            patch.object(app, "_MASCOT_PLACEMENT_ACTIVE", True),
            patch.object(app, "kitty_graphics_supported", return_value=True),
            patch.object(app, "terminal_size", return_value=(175, 45)),
            patch.object(app, "clear_screen"),
            patch.object(app, "_show_presentation") as show_presentation,
        ):
            app._clear_screen()
            self.assertFalse(app._MASCOT_PLACEMENT_ACTIVE)

        show_presentation.assert_called_once_with(kitty_mascot=True)

    def test_clear_uses_text_layout_on_narrow_terminal(self):
        with (
            patch.object(app, "_MASCOT_SESSION_ENABLED", True),
            patch.object(app, "kitty_graphics_supported", return_value=True),
            patch.object(app, "terminal_size", return_value=(100, 40)),
            patch.object(app, "clear_screen"),
            patch.object(app, "_show_presentation") as show_presentation,
        ):
            app._clear_screen()

        show_presentation.assert_called_once_with(kitty_mascot=False)


if __name__ == "__main__":
    unittest.main()
