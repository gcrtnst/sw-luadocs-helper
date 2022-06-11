import sw_luadocs.extract
import unittest


class TestEncodeSectionName(unittest.TestCase):
    def test_validate_convert(self):
        section_name_bin = sw_luadocs.extract.encode_section_name(0)
        self.assertEqual(section_name_bin, b"0\x00\x00\x00\x00\x00\x00\x00")

    def test_validate_value_error(self):
        for section_name in ["/0", ".23456789"]:
            with self.subTest(section_name=section_name):
                with self.assertRaises(ValueError):
                    sw_luadocs.extract.encode_section_name(section_name)

    def test_main(self):
        for input_section_name, expected_section_name_bin in [
            ("", b"\x00\x00\x00\x00\x00\x00\x00\x00"),
            (".rdata", b".rdata\x00\x00"),
            (".2345678", b".2345678"),
        ]:
            with self.subTest(section_name=input_section_name):
                actual_section_name_bin = sw_luadocs.extract.encode_section_name(
                    input_section_name
                )
                self.assertEqual(actual_section_name_bin, expected_section_name_bin)
