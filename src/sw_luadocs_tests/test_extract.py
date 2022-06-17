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


class TestExtractStrings(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.extract_strings("")

    def test_main(self):
        for input_section_bin, expected_ext_txt_set in [
            (b"", set()),
            (b" ", set()),
            (b"\x00", set()),
            (b" \x00", {" "}),
            (b"~\x00", {"~"}),
            (b"\t\x00", {"\t"}),
            (b"\r\x00", {"\r"}),
            (b"\n\x00", {"\n"}),
            (b"\x00 \x00", {" "}),
            (b"a\x00b", {"a"}),
            (b"a\x00b\x00", {"a", "b"}),
            (b"a\x00b\x00", {"a", "b"}),
            (
                b"\x1F\xF3\xAB\x03abc\x00\x5e\xc2\x5c\x81def\x00\x07\x31\x56\xa8",
                {"abc", "def"},
            ),
        ]:
            with self.subTest(section_bin=input_section_bin):
                actual_ext_txt_set = sw_luadocs.extract.extract_strings(
                    input_section_bin
                )
                self.assertEqual(actual_ext_txt_set, expected_ext_txt_set)


class TestCalcLevenshteinDistance(unittest.TestCase):
    def test_validate_convert(self):
        ld = sw_luadocs.extract.calc_levenshtein_distance(0, 0)
        self.assertEqual(ld, 0)

    def test_main(self):
        for input_s, input_t, expected_ld in [
            ("", "", 0),
            ("", "abc", 3),
            ("abc", "", 3),
            ("abc", "abc", 0),
            ("ab", "abc", 1),
            ("abc", "ab", 1),
            ("abc", "abd", 1),
            ("abcde", "abcde", 0),
            ("abde", "abcde", 1),
            ("abcde", "abde", 1),
            ("abcde", "abdde", 1),
            ("kitten", "sitting", 3),
            ("Sunday", "Saturday", 3),
        ]:
            with self.subTest(s=input_s, t=input_t):
                actual_ld = sw_luadocs.extract.calc_levenshtein_distance(
                    input_s, input_t
                )
                self.assertEqual(actual_ld, expected_ld)


class TestMatchSingle(unittest.TestCase):
    def test_validate_convert(self):
        best_ext_txt, best_ld = sw_luadocs.extract.match_single(1, [1, 2])
        self.assertEqual(best_ext_txt, "1")
        self.assertEqual(best_ld, 0)

    def test_empty(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_single("", set())

    def test_main(self):
        for (
            input_ocr_txt,
            input_ext_txt_set,
            expected_best_ext_txt,
            expected_best_ld,
        ) in [
            ("", {""}, "", 0),
            ("", {"1"}, "1", 1),
            ("", {"", "1"}, "", 0),
            ("", ["1", "2"], "1", 1),
            ("", ["2", "1"], "1", 1),
            ("123", {"145", "623"}, "623", 1),
            (
                "Sunday",
                {"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"},
                "Monday",
                2,
            ),
        ]:
            with self.subTest(ocr_txt=input_ocr_txt, ext_txt_set=input_ext_txt_set):
                actual_best_ext_txt, actual_best_ld = sw_luadocs.extract.match_single(
                    input_ocr_txt, input_ext_txt_set
                )
                self.assertEqual(actual_best_ext_txt, expected_best_ext_txt)
                self.assertEqual(actual_best_ld, expected_best_ld)
