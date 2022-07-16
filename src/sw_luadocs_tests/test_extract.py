import sw_luadocs.extract
import sw_luadocs.flatdoc
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


class TestNgramInit(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.Ngram("", n=0)

    def test_main(self):
        for input_txt, input_n, expected_n, expected_txt, expected_bag in [
            ("", 1, 1, "", frozenset()),
            ("abc", 1, 1, "abc", frozenset(["a", "b", "c"])),
            (123, "1", 1, "123", frozenset(["1", "2", "3"])),
            ("", 3, 3, "", frozenset()),
            ("a", 3, 3, "a", frozenset(["\0\0a", "\0a\0", "a\0\0"])),
            (
                "abcde",
                3,
                3,
                "abcde",
                frozenset(["\0\0a", "\0ab", "abc", "bcd", "cde", "de\0", "e\0\0"]),
            ),
        ]:
            with self.subTest(txt=input_txt, n=input_n):
                actual_ngram = sw_luadocs.extract.Ngram(input_txt, n=input_n)
                self.assertEqual(actual_ngram.n, expected_n)
                self.assertEqual(actual_ngram.txt, expected_txt)
                self.assertEqual(actual_ngram.bag, expected_bag)


class TestMatchTxt(unittest.TestCase):
    def test_validate_convert(self):
        best_ext_txt, best_ld = sw_luadocs.extract.match_txt(1, [1, 2])
        self.assertEqual(best_ext_txt, "1")
        self.assertEqual(best_ld, 0)

    def test_empty(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_txt("", set())

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
                (
                    actual_best_ext_txt,
                    actual_best_ld,
                ) = sw_luadocs.extract.match_txt(input_ocr_txt, input_ext_txt_set)
                self.assertEqual(actual_best_ext_txt, expected_best_ext_txt)
                self.assertEqual(actual_best_ld, expected_best_ld)


class TestMatchFlatElem(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.match_flatelem("a", {"a"})

    def test_main(self):
        flatelem, ld = sw_luadocs.extract.match_flatelem(
            sw_luadocs.flatdoc.FlatElem(txt="", kind="code"), {"1"}
        )
        self.assertEqual(flatelem, sw_luadocs.flatdoc.FlatElem(txt="1", kind="code"))
        self.assertEqual(ld, 1)


class TestMatchFlatDoc(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.match_flatdoc("a", {"a"})

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_set,
            expected_ext_flatdoc,
            expected_ld,
        ) in [
            ([], {"1"}, [], 0),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="123", kind="head")],
                {"145", "623"},
                [sw_luadocs.flatdoc.FlatElem(txt="623", kind="head")],
                1,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="123", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="785", kind="code"),
                ],
                {"145", "623"},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="623", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="145", kind="code"),
                ],
                3,
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc, ext_txt_set=input_ext_txt_set
            ):
                actual_ext_flatdoc, actual_ld = sw_luadocs.extract.match_flatdoc(
                    input_ocr_flatdoc, input_ext_txt_set
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_ld, expected_ld)
