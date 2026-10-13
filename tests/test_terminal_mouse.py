import io
import unittest
from unittest.mock import patch

from vulpnix.cli.terminal import copy_text_to_clipboard, MouseTextSelection, _parse_sgr_mouse_event, highlight_columns, extract_selected_text


class SGRMouseEventTests(unittest.TestCase):
    def test_parses_left_button_press(self):
        self.assertEqual(
            _parse_sgr_mouse_event("\033[<0;10;3M"),
            (0, 10, 3, False),
        )

    def test_parses_drag_motion(self):
        self.assertEqual(
            _parse_sgr_mouse_event("\033[<32;11;4M"),
            (32, 11, 4, False),
        )

    def test_parses_left_button_release(self):
        self.assertEqual(
            _parse_sgr_mouse_event("\033[<0;11;4m"),
            (0, 11, 4, True),
        )

    def test_parses_wheel_events(self):
        self.assertEqual(
            _parse_sgr_mouse_event("\033[<64;10;3M"),
            (64, 10, 3, False),
        )
        self.assertEqual(
            _parse_sgr_mouse_event("\033[<65;10;3M"),
            (65, 10, 3, False),
        )

    def test_selection_spans_lines_and_normalizes_drag_direction(self):
        selection = MouseTextSelection(anchor=(4, 3), focus=(2, 5))

        self.assertEqual(selection.bounds, ((2, 5), (4, 3)))
        self.assertFalse(selection.contains(2, 4))
        self.assertTrue(selection.contains(2, 5))
        self.assertTrue(selection.contains(3, 0))
        self.assertTrue(selection.contains(3, 79))
        self.assertTrue(selection.contains(4, 3))
        self.assertFalse(selection.contains(4, 4))
        self.assertFalse(selection.contains(1, 10))

    def test_selection_column_ranges_cover_intermediate_lines(self):
        selection = MouseTextSelection(anchor=(1, 4), focus=(3, 7))

        self.assertEqual(selection.column_range(0), None)
        self.assertEqual(selection.column_range(1), (4, None))
        self.assertEqual(selection.column_range(2), (0, None))
        self.assertEqual(selection.column_range(3), (0, 7))
        self.assertEqual(selection.column_range(4), None)

    def test_highlights_selected_columns(self):
        self.assertEqual(
            highlight_columns("abcde", 1, 4),
            "a\033[7mbcd\033[27me",
        )

    def test_highlighting_strips_ansi_and_supports_wide_characters(self):
        self.assertEqual(
            highlight_columns("\033[31ma界e\u0301z\033[0m", 1, 3),
            "a\033[7m界\033[27me\u0301z",
        )

    def test_rejects_invalid_mouse_sequences(self):
        for sequence in (
            "\033[A",
            "\033[<invalid",
            "\033[<0;0;3M",
            "\033[<0;10;0M",
        ):
            with self.subTest(sequence=sequence):
                self.assertIsNone(_parse_sgr_mouse_event(sequence))


class ClipboardTests(unittest.TestCase):
    def test_extracts_multiline_selection_and_strips_ansi(self):
        selection = MouseTextSelection(anchor=(0, 1), focus=(2, 2))
        lines = ["one", "\033[31mtwo\033[0m", "three"]

        self.assertEqual(
            extract_selected_text(lines, selection),
            "ne\ntwo\nthr",
        )

    def test_empty_click_selection_does_not_copy_text(self):
        selection = MouseTextSelection(anchor=(0, 2), focus=(0, 2))

        self.assertEqual(extract_selected_text(["hello"], selection), "")

    def test_mouse_selection_release_copies_selected_text(self):
        from vulpnix.cli import app

        keys = iter((
            "\033[<0;2;1M",
            "\033[<32;4;1M",
            "\033[<0;4;1m",
            "\r",
        ))
        with (
            patch.object(app, "read_key", side_effect=lambda **_: next(keys)),
            patch.object(app, "_render_shell"),
            patch.object(app, "terminal_size", return_value=(80, 24)),
            patch.object(app, "copy_text_to_clipboard") as copy_text,
        ):
            result = app._read_command(["hello"], [], 0)

        self.assertEqual(result, ("", 0))
        copy_text.assert_called_once_with("ell")

    def test_copy_uses_real_osc52_control_sequences(self):
        class TTYBuffer(io.StringIO):
            def isatty(self):
                return True

        output = TTYBuffer()
        with patch(
            "vulpnix.cli.terminal.sys.stdout", output
        ):
            result = copy_text_to_clipboard("Hello")

        self.assertTrue(result)
        self.assertEqual(output.getvalue(), "\x1b]52;c;SGVsbG8=\x1b\\")


if __name__ == "__main__":
    unittest.main()
