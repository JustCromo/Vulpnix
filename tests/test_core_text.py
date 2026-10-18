import unittest

from vulpnix.core.text import display_text, format_uptime, printable


class PrintableTests(unittest.TestCase):
    def test_non_printable_characters_are_replaced_not_passed_through(self):
        self.assertEqual(printable("a\x00b\x1b[31mc\n"), "a\ufffdb\ufffd[31mc\ufffd")

    def test_ordinary_text_is_unchanged(self):
        self.assertEqual(printable("Arch Linux 7.2.8-arch1-2"), "Arch Linux 7.2.8-arch1-2")


class DisplayTextTests(unittest.TestCase):
    def test_missing_values_read_unavailable(self):
        self.assertEqual(display_text(None), "Unavailable")
        self.assertEqual(display_text(""), "Unavailable")

    def test_long_values_are_bounded_with_an_ellipsis(self):
        # Same rule the terminal used before: over the limit -> first 77 + "…".
        self.assertEqual(display_text("x" * 200), "x" * 77 + "…")
        self.assertEqual(display_text("x" * 81), "x" * 77 + "…")
        self.assertEqual(display_text("x" * 80), "x" * 80)

    def test_control_characters_are_made_safe_before_truncation(self):
        self.assertNotIn("\x1b", display_text("host\x1b[2Jname"))


class UptimeTests(unittest.TestCase):
    def test_formats_days_hours_minutes(self):
        self.assertEqual(format_uptime(90061), "1d 1h 1m")
        self.assertEqual(format_uptime(3900), "1h 5m")
        self.assertEqual(format_uptime(86400), "1d")
        self.assertEqual(format_uptime(59), "0m")
        self.assertEqual(format_uptime(0), "0m")

    def test_unknown_uptime_reads_unavailable(self):
        self.assertEqual(format_uptime(None), "Unavailable")


if __name__ == "__main__":
    unittest.main()
