import numpy as np
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


class TestCalcLevenshteinDP(unittest.TestCase):
    def test_validate_convert(self):
        lddp = sw_luadocs.extract.calc_levenshtein_dp(1, 2)
        self.assertTrue(
            np.array_equal(
                lddp,
                [
                    [0, 1],
                    [1, 1],
                ],
            )
        )

    def test_main(self):
        for input_s, input_t, expected_lddp in [
            (
                "",
                "",
                [
                    [0],
                ],
            ),
            (
                "",
                "abc",
                [
                    [0, 1, 2, 3],
                ],
            ),
            (
                "abc",
                "",
                [
                    [0],
                    [1],
                    [2],
                    [3],
                ],
            ),
            (
                "abc",
                "abc",
                [
                    [0, 1, 2, 3],
                    [1, 0, 1, 2],
                    [2, 1, 0, 1],
                    [3, 2, 1, 0],
                ],
            ),
            (
                "ac",
                "abc",
                [
                    [0, 1, 2, 3],
                    [1, 0, 1, 2],
                    [2, 1, 1, 1],
                ],
            ),
            (
                "abc",
                "ac",
                [
                    [0, 1, 2],
                    [1, 0, 1],
                    [2, 1, 1],
                    [3, 2, 1],
                ],
            ),
            (
                "abc",
                "adc",
                [
                    [0, 1, 2, 3],
                    [1, 0, 1, 2],
                    [2, 1, 1, 2],
                    [3, 2, 2, 1],
                ],
            ),
            (
                "kitten",
                "sitting",
                [
                    [0, 1, 2, 3, 4, 5, 6, 7],
                    [1, 1, 2, 3, 4, 5, 6, 7],
                    [2, 2, 1, 2, 3, 4, 5, 6],
                    [3, 3, 2, 1, 2, 3, 4, 5],
                    [4, 4, 3, 2, 1, 2, 3, 4],
                    [5, 5, 4, 3, 2, 2, 3, 4],
                    [6, 6, 5, 4, 3, 3, 2, 3],
                ],
            ),
        ]:
            with self.subTest(s=input_s, t=input_t):
                actual_lddp = sw_luadocs.extract.calc_levenshtein_dp(input_s, input_t)
                self.assertTrue(np.array_equal(actual_lddp, expected_lddp))


class TestMatchTxtAdv(unittest.TestCase):
    def test_validate_convert(self):
        adv, ld = sw_luadocs.extract.match_txt_adv({1: None, 2: None}, 132, sep=3)
        self.assertEqual(adv, 2)
        self.assertEqual(ld, 0)

    def test_main(self):
        for (
            input_ocr_txt_list,
            input_ext_txt,
            input_sep,
            expected_adv,
            expected_ld,
        ) in [
            ([], "", "", 0, 0),
            ([], "abc", "", 0, 3),
            ([], "", "###", 0, 0),
            (["abc"], "", "", 1, 3),
            (["abc"], "abc", "", 1, 0),
            (["abc"], "", "###", 1, 3),
            (["abc", "def"], "", "", 1, 3),
            (["abc", "def"], "abc", "", 1, 0),
            (["abc", "def"], "abcd", "", 1, 1),
            (["abc", "def"], "abcde", "", 2, 1),
            (["abc", "def"], "abcdef", "", 2, 0),
            (["abc", "def"], "", "###", 1, 3),
            (["abc", "def"], "abc", "###", 1, 0),
            (["abc", "def"], "abc#", "###", 1, 0),
            (["abc", "def"], "abc##", "###", 1, 0),
            (["abc", "def"], "abc###", "###", 1, 0),
            (["abc", "def"], "abc###d", "###", 1, 1),
            (["abc", "def"], "abc###de", "###", 2, 1),
            (["abc", "def"], "abc###def", "###", 2, 0),
            (["abc", "def"], "abc###def#", "###", 2, 1),
            (["abc", "def"], "abc%%%", "%%%", 1, 0),
        ]:
            with self.subTest(
                ocr_txt_list=input_ocr_txt_list, ext_txt=input_ext_txt, sep=input_sep
            ):
                actual_adv, actual_ld = sw_luadocs.extract.match_txt_adv(
                    input_ocr_txt_list, input_ext_txt, sep=input_sep
                )
                self.assertEqual(actual_adv, expected_adv)
                self.assertEqual(actual_ld, expected_ld)


class TestMatchTxtLeft(unittest.TestCase):
    def test_validate_convert(self):
        ext_txt, adv, ld = sw_luadocs.extract.match_txt_left(
            {1: None, 2: None}, [152, 12], sep=5
        )
        self.assertEqual(ext_txt, "152")
        self.assertEqual(adv, 2)
        self.assertEqual(ld, 0)

    def test_empty(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_txt_left(["a"], set())

    def test_main(self):
        for (
            input_ocr_txt_list,
            input_ext_txt_set,
            input_sep,
            expected_ext_txt,
            expected_adv,
            expected_ld,
        ) in [
            ([], {""}, "", "", 0, 0),
            (["abc"], {"def"}, "", "def", 1, 3),
            (["abc", "def"], {"abc###def"}, "###", "abc###def", 2, 0),
            (["abc", "def"], {"abc", "def"}, "", "abc", 1, 0),
            (["def", "abc"], {"abc", "def"}, "", "def", 1, 0),
            (["abc"], {"abd", "bbc"}, "", "abd", 1, 1),
            (["abc", "def"], {"abc", "abc###def"}, "###", "abc###def", 2, 0),
            (["abc", "def"], {"abc", "abc###"}, "###", "abc###", 1, 0),
        ]:
            with self.subTest(
                ocr_txt_list=input_ocr_txt_list,
                ext_txt_set=input_ext_txt_set,
                sep=input_sep,
            ):
                (
                    actual_ext_txt,
                    actual_adv,
                    actual_ld,
                ) = sw_luadocs.extract.match_txt_left(
                    input_ocr_txt_list, input_ext_txt_set, sep=input_sep
                )
                self.assertEqual(actual_ext_txt, expected_ext_txt)
                self.assertEqual(actual_adv, expected_adv)
                self.assertEqual(actual_ld, expected_ld)


class TestMatchTxt(unittest.TestCase):
    def test_validate_convert(self):
        ext_txt_list, ld = sw_luadocs.extract.match_txt(
            {1: None, 2: None}, [13, 2], sep=3
        )
        self.assertEqual(ext_txt_list, ["13", "2"])
        self.assertEqual(ld, 0)

    def test_main(self):
        for (
            input_ocr_txt_list,
            input_ext_txt_set,
            input_sep,
            expected_ext_txt_list,
            expected_ld,
        ) in [
            ([], {""}, "", [], 0),
            (["abc"], {""}, "", [""], 3),
            (["abc"], {"abc"}, "", ["abc"], 0),
            (["abc", "def"], {""}, "", ["", ""], 6),
            (["abc", "def"], {"abc", "def"}, "", ["abc", "def"], 0),
            (["abc", "def"], {"abc###def"}, "###", ["abc###def"], 0),
            (
                ["abc", "def", "ghi"],
                {"abc", "abc###def"},
                "###",
                ["abc###def", "abc"],
                3,
            ),
        ]:
            with self.subTest(
                ocr_txt_list=input_ocr_txt_list,
                ext_txt_set=input_ext_txt_set,
                sep=input_sep,
            ):
                actual_ext_txt_list, actual_ld = sw_luadocs.extract.match_txt(
                    input_ocr_txt_list, input_ext_txt_set, sep=input_sep
                )
                self.assertEqual(actual_ext_txt_list, expected_ext_txt_list)
                self.assertEqual(actual_ld, expected_ld)


class TestMatchFlatDocMonoKind(unittest.TestCase):
    def test_validate_value_error(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_flatdoc_monokind(
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                {"c"},
            )

    def test_validate_convert(self):
        ext_flatdoc, ld = sw_luadocs.extract.match_flatdoc_monokind([], {"a"}, sep=0)
        self.assertEqual(ext_flatdoc, [])
        self.assertEqual(ld, 0)

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_set,
            input_sep,
            expected_ext_flatdoc,
            expected_ld,
        ) in [
            ([], {"a"}, "\n\n", [], 0),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")],
                {"a"},
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")],
                0,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")],
                {"b"},
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="code")],
                1,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")],
                {"a"},
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")],
                0,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="code")],
                {"a", "b"},
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                {"a\n\nb"},
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="a\n\nb", kind="code")],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                {"a", "\nb"},
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="\nb", kind="code"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                {"a,b"},
                ",",
                [sw_luadocs.flatdoc.FlatElem(txt="a,b", kind="code")],
                0,
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_set=input_ext_txt_set,
                sep=input_sep,
            ):
                (
                    actual_ext_flatdoc,
                    actual_ld,
                ) = sw_luadocs.extract.match_flatdoc_monokind(
                    input_ocr_flatdoc, input_ext_txt_set, sep=input_sep
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_ld, expected_ld)


class TestMatchFlatDoc(unittest.TestCase):
    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_set,
            input_sep,
            expected_ext_flatdoc,
            expected_ld,
        ) in [
            ([], {"a"}, ",", [], 0),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
                {"a"},
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
                0,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="head")],
                {"a"},
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
                1,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")],
                {"a"},
                "\n\n",
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                {"a\n\nb"},
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\n\nb", kind="head"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                {"a\n\nb"},
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\n\nb", kind="body"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                {"a\n\nb"},
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\n\nb", kind="code"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                {"a:b"},
                ":",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a:b", kind="code"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                {"a", "b", "c"},
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="a2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                {"a1", "a2", "b1", "b2", "c1", "c2"},
                "\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="a2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="a2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                {"a1\n\na2", "b1\n\nb2", "c1\n\nc2"},
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a1\n\na2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1\n\nb2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1\n\nc2", kind="code"),
                ],
                0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="a2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b2", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c2", kind="code"),
                ],
                {"a1\n\na2!", "b1\n\nb2!", "c1\n\nc2!"},
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a1\n\na2!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b1\n\nb2!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c1\n\nc2!", kind="code"),
                ],
                3,
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_set=input_ext_txt_set,
                sep=input_sep,
            ):
                actual_ext_flatdoc, actual_ld = sw_luadocs.extract.match_flatdoc(
                    input_ocr_flatdoc, input_ext_txt_set, sep=input_sep
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_ld, expected_ld)
