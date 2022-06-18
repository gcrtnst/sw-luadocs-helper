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


class TestGenerateConcatPatterns(unittest.TestCase):
    def test_validate_convert(self):
        cat_txt_tuple_set = sw_luadocs.extract.generate_concat_patterns(
            {1: None, 2: None}, sep=3
        )
        self.assertEqual(cat_txt_tuple_set, {("1", "2"), ("132",)})

    def test_main(self):
        for input_ocr_txt_list, input_sep, expected_cat_txt_tuple_set in [
            ([], ",", set()),
            (["a"], ",", {("a",)}),
            (["a", "b"], ",", {("a", "b"), ("a,b",)}),
            (["a", "b"], ":", {("a", "b"), ("a:b",)}),
            (
                ["a", "b", "c"],
                ",",
                {("a", "b", "c"), ("a", "b,c"), ("a,b", "c"), ("a,b,c",)},
            ),
            (
                ["a", "b", "c", "d"],
                ",",
                {
                    ("a", "b", "c", "d"),
                    ("a", "b", "c,d"),
                    ("a", "b,c", "d"),
                    ("a", "b,c,d"),
                    ("a,b", "c", "d"),
                    ("a,b", "c,d"),
                    ("a,b,c", "d"),
                    ("a,b,c,d",),
                },
            ),
        ]:
            with self.subTest(ocr_txt_list=input_ocr_txt_list, sep=input_sep):
                actual_cat_txt_tuple_set = sw_luadocs.extract.generate_concat_patterns(
                    input_ocr_txt_list, sep=input_sep
                )
                self.assertEqual(actual_cat_txt_tuple_set, expected_cat_txt_tuple_set)


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


class TestMatchMultiple(unittest.TestCase):
    def test_validate_convert(self):
        best_ext_txt_list, best_ld_sum = sw_luadocs.extract.match_multiple(
            {1: None, 2: None}, {3: None, 4: None}
        )
        self.assertEqual(best_ext_txt_list, ["3", "3"])
        self.assertEqual(best_ld_sum, 2)

    def test_main(self):
        for (
            input_ocr_txt_list,
            input_ext_txt_set,
            expected_best_ext_txt_list,
            expected_best_ld_sum,
        ) in [
            ([], {"1"}, [], 0),
            (["123"], {"145", "623"}, ["623"], 1),
            (["123", "785"], {"145", "623"}, ["623", "145"], 3),
        ]:
            with self.subTest(
                ocr_txt_list=input_ocr_txt_list, ext_txt_set=input_ext_txt_set
            ):
                (
                    actual_best_ext_txt_list,
                    actual_best_ld_sum,
                ) = sw_luadocs.extract.match_multiple(
                    input_ocr_txt_list, input_ext_txt_set
                )
                self.assertEqual(actual_best_ext_txt_list, expected_best_ext_txt_list)
                self.assertEqual(actual_best_ld_sum, expected_best_ld_sum)


class TestMatchConcat(unittest.TestCase):
    def test_validate_convert(self):
        best_ext_txt_list, best_ld = sw_luadocs.extract.match_concat(
            {1: None, 2: None}, {12: None, 34: None}, sep=5
        )
        self.assertEqual(best_ext_txt_list, ["12"])
        self.assertEqual(best_ld, 1)

    def test_empty(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_concat([], {"a"})

    def test_main(self):
        for (
            input_ocr_txt_list,
            input_ext_txt_set,
            input_sep,
            expected_best_ext_txt_list,
            expected_best_ld,
        ) in [
            (["a"], {"a"}, ",", ["a"], 0),
            (["a"], {"b"}, ",", ["b"], 1),
            (["a", "b"], {"a,b"}, ",", ["a,b"], 0),
            (["a", "b"], {"a:b"}, ",", ["a:b"], 1),
            (["a", "b"], {"a", "b"}, ",", ["a", "b"], 0),
            (["a", "b"], {"a"}, ",", ["a", "a"], 1),
            (["a", "b"], {"a", "b", "a,b"}, ",", ["a", "b"], 0),
            (["a", "b"], {"a", "a:b"}, ",", ["a", "a"], 1),
            (["a", "b", "c"], {"a,b", "b,c"}, ",", ["a,b", "b,c"], 2),
        ]:
            with self.subTest(
                ocr_txt_list=input_ocr_txt_list,
                ext_txt_set=input_ext_txt_set,
                sep=input_sep,
            ):
                (
                    actual_best_ext_txt_list,
                    actual_best_ld,
                ) = sw_luadocs.extract.match_concat(
                    input_ocr_txt_list, input_ext_txt_set, sep=input_sep
                )
                self.assertEqual(actual_best_ext_txt_list, expected_best_ext_txt_list)
                self.assertEqual(actual_best_ld, expected_best_ld)
