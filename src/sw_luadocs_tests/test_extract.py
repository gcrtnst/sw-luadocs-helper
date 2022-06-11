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

    def test_validate_convert_memo(self):
        ld = sw_luadocs.extract.calc_levenshtein_distance(
            "a", "a", memo={("a", "a"): "0"}
        )
        self.assertEqual(ld, 0)

    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.calc_levenshtein_distance("", "", memo=0)

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

    def test_memo(self):
        for input_s, input_t, input_memo, expected_ld, expected_memo in [
            ("a", "a", {("a", "a"): 10}, 10, {("a", "a"): 10}),
            ("ab", "ab", {("b", "b"): 10}, 10, {("b", "b"): 10, ("ab", "ab"): 10}),
            (
                "ac",
                "bc",
                {("ac", "c"): -1},
                0,
                {("ac", "c"): -1, ("c", "bc"): 1, ("c", "c"): 0, ("ac", "bc"): 0},
            ),
            (
                "ac",
                "bc",
                {("c", "bc"): -1},
                0,
                {("ac", "c"): 1, ("c", "bc"): -1, ("c", "c"): 0, ("ac", "bc"): 0},
            ),
            (
                "ac",
                "bc",
                {("c", "c"): -1},
                0,
                {("ac", "c"): 0, ("c", "bc"): 0, ("c", "c"): -1, ("ac", "bc"): 0},
            ),
        ]:
            with self.subTest(s=input_s, t=input_t, memo=input_memo):
                actual_memo = input_memo.copy()
                actual_ld = sw_luadocs.extract.calc_levenshtein_distance(
                    input_s, input_t, memo=actual_memo
                )
                self.assertEqual(actual_ld, expected_ld)
                self.assertEqual(actual_memo, expected_memo)
