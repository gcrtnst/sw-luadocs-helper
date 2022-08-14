import sw_luadocs.main
import unittest


class TestParseNewlineArgument(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.main.parse_newline_argument("invalid")

    def test_main(self):
        for input_s, expected_newline in [
            ("LF", "\n"),
            ("CR", "\r"),
            ("CRLF", "\r\n"),
            ("lf", "\n"),
            ("cr", "\r"),
            ("crlf", "\r\n"),
        ]:
            with self.subTest(s=input_s):
                actual_newline = sw_luadocs.main.parse_newline_argument(input_s)
                self.assertEqual(actual_newline, expected_newline)
