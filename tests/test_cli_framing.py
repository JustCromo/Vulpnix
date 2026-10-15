"""Tests for the shared interactive command-frame renderer."""

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from vulpnix.cli import app
from vulpnix.cli.terminal import display_width


class CommandFrameTests(unittest.TestCase):
    def setUp(self):
        app._OUTPUT_LAYOUT_CACHE = None

    def frame_lines(self, title, body):
        lines = [f"{app._COMMAND_FRAME_START_PREFIX}{title}\x00"]
        lines.extend(body.splitlines())
        lines.append(app._COMMAND_FRAME_END_MARKER)
        return lines

    def test_command_title_identifies_each_command_area(self):
        self.assertEqual(app._command_frame_title("help"), "HELP")
        self.assertEqual(app._command_frame_title("info"), "INFO")
        self.assertEqual(app._command_frame_title("scan --details"), "SCAN")
        self.assertEqual(
            app._command_frame_title("scan packages --details"),
            "SCAN / PACKAGES",
        )
        self.assertIsNone(app._command_frame_title("clear"))

    def test_append_output_marks_a_complete_command_section(self):
        lines = []
        app._append_output(
            lines,
            "COMMANDS\n  help | Show available commands",
            title="HELP",
        )

        self.assertTrue(lines[0].startswith(app._COMMAND_FRAME_START_PREFIX))
        self.assertEqual(lines[-1], app._COMMAND_FRAME_END_MARKER)
        self.assertIn("COMMANDS", lines)
        self.assertIn("  help | Show available commands", lines)

    def test_command_output_renders_as_a_closed_box(self):
        source = self.frame_lines(
            "HELP",
            "COMMANDS\n"
            "  help              │ Show available commands\n"
            "  info              │ Project information\n"
            "\n"
            "SCAN AREAS\n"
            "  scan host         │ Host and OS information",
        )

        rendered = app._render_command_sections(source, 64)
        plain = [_strip(line) for line in rendered]

        self.assertTrue(plain[0].startswith("╭─ VULPNIX / HELP"))
        self.assertTrue(plain[-1].startswith("╰"))
        self.assertTrue(all(display_width(line) <= 64 for line in rendered))
        self.assertTrue(any(line.startswith("├") for line in plain))
        self.assertTrue(any("COMMANDS" in line for line in plain))
        self.assertTrue(any("SCAN AREAS" in line for line in plain))
        self.assertFalse(any("VULPNIX_COMMAND_FRAME" in line for line in plain))


    def test_frame_border_lines_have_exactly_the_same_width(self):
        rendered = app._render_command_frame(
            "SCAN / PACKAGE VULNERABILITY ASSESSMENT",
            [
                "PACKAGE INVENTORY",
                "Package metadata collected successfully.",
                "PACKAGE VULNERABILITY AUDIT",
                "Advisory source coverage needs review.",
            ],
            64,
        )
        widths = [display_width(line) for line in rendered]
        self.assertTrue(all(width == 64 for width in widths), widths)
        self.assertTrue(_strip(rendered[0]).startswith("╭─ VULPNIX /"))
        self.assertTrue(_strip(rendered[-1]).startswith("╰"))


    def test_help_description_wraps_under_its_own_column(self):
        output = io.StringIO()
        with (
            patch.object(app, "terminal_size", return_value=(96, 40)),
            redirect_stdout(output),
        ):
            app._show_help()

        lines = output.getvalue().splitlines()
        description_line = next(
            line for line in lines
            if "User and privilege assessment" in line
        )
        continuation_line = next(
            line for line in lines
            if "inventory" in line and "scan users" not in line
        )

        self.assertEqual(
            description_line.index("│"),
            continuation_line.index("│"),
            "Wrapped description must stay aligned under the description column.",
        )
        self.assertTrue(continuation_line.index("│") > 2)

    def test_frame_reflows_when_terminal_width_changes(self):
        long_text = (
            "Package advisory correlation needs network access and incomplete "
            "coverage must never be interpreted as proof that the packages are secure."
        )
        source = self.frame_lines("SCAN / PACKAGES", long_text)

        wide = app._render_command_sections(source, 80)
        narrow = app._render_command_sections(source, 38)

        self.assertTrue(all(display_width(line) <= 80 for line in wide))
        self.assertTrue(all(display_width(line) <= 38 for line in narrow))
        self.assertTrue(_strip(narrow[0]).startswith("╭─ VULPNIX /"))
        self.assertTrue(_strip(narrow[-1]).startswith("╰"))
        self.assertIn("incomplete", " ".join(_strip(line) for line in narrow))

    def test_fit_output_to_width_renders_frame_markers(self):
        source = self.frame_lines(
            "INFO",
            "DESIGN GOAL\nEvidence-backed results and fewer false positives.",
        )
        rendered = app._fit_output_to_width(
            source,
            58,
            reserve_mascot=False,
        )
        plain = [_strip(line) for line in rendered]

        self.assertTrue(plain[0].startswith("╭─ VULPNIX / INFO"))
        self.assertTrue(plain[-1].startswith("╰"))
        self.assertIn("DESIGN GOAL", " ".join(plain))
        self.assertTrue(all(display_width(line) <= 58 for line in rendered))


def _strip(text):
    """Strip ANSI CSI sequences for layout assertions."""
    result = []
    index = 0
    while index < len(text):
        if text[index] == "\x1b" and index + 1 < len(text) and text[index + 1] == "[":
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



class ANSIFrameWrappingTests(unittest.TestCase):
    def test_uniform_ansi_style_survives_wrapping(self):
        style = "\033[1;38;2;255;112;112m"
        reset = "\033[0m"
        original = style + "  Coverage qualifier: partial checks need review." + reset

        for width in (20, 36):
            with self.subTest(width=width):
                result = app._wrap_command_frame_line(original, width)
                self.assertTrue(all(display_width(line) <= width for line in result))
                self.assertTrue(all(line.startswith(style) for line in result))
                self.assertTrue(all(line.endswith(reset) for line in result))
                visible = " ".join(
                    app._strip_terminal_styles(line).strip() for line in result
                )
                self.assertIn("Coverage qualifier: partial checks", visible)


if __name__ == "__main__":
    unittest.main()
