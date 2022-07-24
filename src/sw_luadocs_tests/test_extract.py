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


class TestNgramEq(unittest.TestCase):
    def test_main(self):
        for input_self, input_other, expected_result in [
            (sw_luadocs.extract.Ngram("", n=1), None, NotImplemented),
            (
                sw_luadocs.extract.Ngram("", n=1),
                sw_luadocs.extract.Ngram("", n=1),
                True,
            ),
            (
                sw_luadocs.extract.Ngram("", n=1),
                sw_luadocs.extract.Ngram("a", n=1),
                False,
            ),
            (
                sw_luadocs.extract.Ngram("", n=1),
                sw_luadocs.extract.Ngram("", n=2),
                False,
            ),
        ]:
            with self.subTest(input_self=input_self, input_other=input_other):
                actual_result = input_self.__eq__(input_other)
                self.assertEqual(actual_result, expected_result)


class TestCalcJaccardSimilarity(unittest.TestCase):
    def test_invalid_type(self):
        for ngram1, ngram2 in [
            (None, sw_luadocs.extract.Ngram("")),
            (sw_luadocs.extract.Ngram(""), None),
        ]:
            with self.subTest(ngram1=ngram1, ngram2=ngram2):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.calc_jaccard_similarity(ngram1, ngram2)

    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.calc_jaccard_similarity(
                sw_luadocs.extract.Ngram("", n=1), sw_luadocs.extract.Ngram("", n=2)
            )

    def test_main(self):
        for input_ngram1, input_ngram2, expected_score in [
            (sw_luadocs.extract.Ngram("", n=1), sw_luadocs.extract.Ngram("", n=1), 1.0),
            (
                sw_luadocs.extract.Ngram("a", n=1),
                sw_luadocs.extract.Ngram("", n=1),
                0.0,
            ),
            (
                sw_luadocs.extract.Ngram("", n=1),
                sw_luadocs.extract.Ngram("a", n=1),
                0.0,
            ),
            (
                sw_luadocs.extract.Ngram("a", n=1),
                sw_luadocs.extract.Ngram("a", n=1),
                1.0,
            ),
            (
                sw_luadocs.extract.Ngram("a", n=1),
                sw_luadocs.extract.Ngram("b", n=1),
                0.0,
            ),
            (
                sw_luadocs.extract.Ngram("abc", n=1),
                sw_luadocs.extract.Ngram("abd", n=1),
                0.5,
            ),
        ]:
            with self.subTest(ngram1=input_ngram1, ngram2=input_ngram2):
                actual_score = sw_luadocs.extract.calc_jaccard_similarity(
                    input_ngram1, input_ngram2
                )
                self.assertIs(type(actual_score), float)
                self.assertEqual(actual_score, expected_score)


class TestCalcLengthSimilarity(unittest.TestCase):
    def test_invalid_value(self):
        for len1, len2 in [(-1, 0), (0, -1)]:
            with self.subTest(len1=len1, len2=len2):
                with self.assertRaises(ValueError):
                    sw_luadocs.extract.calc_length_similarity(len1, len2)

    def test_main(self):
        for input_len1, input_len2, expected_score in [
            (0, 0, 1.0),
            (0, 1, 0.0),
            (1, 0, 0.0),
            (1, 4, 0.25),
            (4, 1, 0.25),
            (1, 2, 0.5),
            (2, 1, 0.5),
            (3, 4, 0.75),
            (4, 3, 0.75),
        ]:
            with self.subTest(len1=input_len1, len2=input_len2):
                actual_score = sw_luadocs.extract.calc_length_similarity(
                    input_len1, input_len2
                )
                self.assertIs(type(actual_score), float)
                self.assertEqual(actual_score, expected_score)


class TestCalcScore(unittest.TestCase):
    def test_invalid_type(self):
        for ngram1, ngram2 in [
            ("1", sw_luadocs.extract.Ngram("2")),
            (sw_luadocs.extract.Ngram("1"), "2"),
        ]:
            with self.subTest(ngram1=ngram1, ngram2=ngram2):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.calc_score(ngram1, ngram2)

    def test_main(self):
        for input_ngram1, input_ngram2, expected_score in [
            (sw_luadocs.extract.Ngram("", n=1), sw_luadocs.extract.Ngram("", n=1), 1.0),
            (
                sw_luadocs.extract.Ngram("abc", n=1),
                sw_luadocs.extract.Ngram("abc", n=1),
                1.0,
            ),
            (
                sw_luadocs.extract.Ngram("abc", n=1),
                sw_luadocs.extract.Ngram("abcabcabcabc", n=1),
                0.25,
            ),
            (
                sw_luadocs.extract.Ngram("abcabcabcabc", n=1),
                sw_luadocs.extract.Ngram("abc", n=1),
                0.25,
            ),
            (
                sw_luadocs.extract.Ngram("abc", n=1),
                sw_luadocs.extract.Ngram("abd", n=1),
                0.5,
            ),
            (
                sw_luadocs.extract.Ngram("abd", n=1),
                sw_luadocs.extract.Ngram("abc", n=1),
                0.5,
            ),
            (
                sw_luadocs.extract.Ngram("abcabcabcabc", n=1),
                sw_luadocs.extract.Ngram("abd", n=1),
                0.125,
            ),
            (
                sw_luadocs.extract.Ngram("abd", n=1),
                sw_luadocs.extract.Ngram("abcabcabcabc", n=1),
                0.125,
            ),
        ]:
            with self.subTest(ngram1=input_ngram1, ngram2=input_ngram2):
                actual_score = sw_luadocs.extract.calc_score(input_ngram1, input_ngram2)
                self.assertIs(type(actual_score), float)
                self.assertEqual(actual_score, expected_score)


class TestNgramDatabaseInit(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.NgramDatabase(set(), n=0)

    def test_main(self):
        for input_txt_set, input_n, expected_db_n, expected_db_db in [
            (set(), 1, 1, frozenset()),
            (set(), "1", 1, frozenset()),
            (
                {"a", "b", "c"},
                1,
                1,
                frozenset(
                    [
                        sw_luadocs.extract.Ngram("a", n=1),
                        sw_luadocs.extract.Ngram("b", n=1),
                        sw_luadocs.extract.Ngram("c", n=1),
                    ]
                ),
            ),
            (
                {"a", "b", "c"},
                2,
                2,
                frozenset(
                    [
                        sw_luadocs.extract.Ngram("a", n=2),
                        sw_luadocs.extract.Ngram("b", n=2),
                        sw_luadocs.extract.Ngram("c", n=2),
                    ]
                ),
            ),
        ]:
            with self.subTest(txt_set=input_txt_set, n=input_n):
                actual_db = sw_luadocs.extract.NgramDatabase(input_txt_set, n=input_n)
                self.assertEqual(actual_db.n, expected_db_n)
                self.assertEqual(frozenset(actual_db.db), expected_db_db)


class TestMatchTxtSingle(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.match_txt_single("", {"a"})

    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_txt_single(
                "", sw_luadocs.extract.NgramDatabase([])
            )

    def test_main(self):
        for input_ocr_txt, input_ext_txt_db, expected_ext_txt, expected_score in [
            ("", sw_luadocs.extract.NgramDatabase(["a"], n=1), "a", 0.0),
            (
                "abcabcabcabc",
                sw_luadocs.extract.NgramDatabase(["abd"], n=1),
                "abd",
                0.125,
            ),
            (
                123123123123,
                sw_luadocs.extract.NgramDatabase(["124"], n=1),
                "124",
                0.125,
            ),
            (
                "abc",
                sw_luadocs.extract.NgramDatabase(["ddd", "add", "abd", "abc"], n=1),
                "abc",
                1.0,
            ),
            (
                "abc",
                sw_luadocs.extract.NgramDatabase(
                    ["abd", "adb", "bad", "dab", "bda", "dba"], n=1
                ),
                "abd",
                0.5,
            ),
        ]:
            with self.subTest(ocr_txt=input_ocr_txt, ext_txt_db=input_ext_txt_db):
                actual_ext_txt, actual_score = sw_luadocs.extract.match_txt_single(
                    input_ocr_txt, input_ext_txt_db
                )
                self.assertEqual(actual_ext_txt, expected_ext_txt)
                self.assertEqual(actual_score, expected_score)


class TestMatchTxtLeft(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.match_txt_left([], set())

    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_txt_left(
                [], sw_luadocs.extract.NgramDatabase(["a"])
            )

    def test_main(self):
        for (
            input_ocr_txt_list,
            input_ext_txt_db,
            input_sep,
            expected_ext_txt,
            expected_adv,
            expected_score,
        ) in [
            (
                ["a"],
                sw_luadocs.extract.NgramDatabase(["ab", "bc"], n=1),
                "\n",
                "ab",
                1,
                0.25,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramDatabase(["a"], n=3),
                ",",
                "a",
                1,
                1.0,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramDatabase(["a,b"], n=3),
                ",",
                "a,b",
                2,
                1.0,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramDatabase(["a,b,c"], n=3),
                ",",
                "a,b,c",
                3,
                1.0,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramDatabase(["a:b:c"], n=3),
                ":",
                "a:b:c",
                3,
                1.0,
            ),
            (
                [1, 2, 3],
                sw_luadocs.extract.NgramDatabase(["14243"], n=3),
                4,
                "14243",
                3,
                1.0,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramDatabase(["a", "a,b", "a,b,c"], n=3),
                ",",
                "a",
                1,
                1.0,
            ),
            (
                ["abc", "def", "ghi"],
                sw_luadocs.extract.NgramDatabase(
                    ["ghi", "abc,def", "abc:def:jkl"], n=1
                ),
                ":",
                "abc,def",
                2,
                0.75,
            ),
        ]:
            with self.subTest(
                ocr_txt_list=input_ocr_txt_list,
                ext_txt_db=input_ext_txt_db,
                sep=input_sep,
            ):
                (
                    actual_ext_txt,
                    actual_adv,
                    actual_score,
                ) = sw_luadocs.extract.match_txt_left(
                    input_ocr_txt_list, input_ext_txt_db, sep=input_sep
                )
                self.assertEqual(actual_ext_txt, expected_ext_txt)
                self.assertEqual(actual_adv, expected_adv)
                self.assertEqual(actual_score, expected_score)


class TestMatchTxtPack(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.match_txt_pack([], set())

    def test_main(self):
        for (
            input_ocr_txt_list,
            input_ext_txt_db,
            input_sep,
            expected_ext_txt_list,
            expected_score,
        ) in [
            ([], sw_luadocs.extract.NgramDatabase([""], n=1), "", [], 1.0),
            (["abc"], sw_luadocs.extract.NgramDatabase(["def"], n=1), "", ["def"], 0.0),
            (
                ["abc", "def"],
                sw_luadocs.extract.NgramDatabase(["abg", "deh"], n=1),
                "",
                ["abg", "deh"],
                0.5,
            ),
            (
                ["abc", "def"],
                sw_luadocs.extract.NgramDatabase(["abcdef"], n=1),
                "",
                ["abcdef"],
                1.0,
            ),
            (
                ["abc", "def"],
                sw_luadocs.extract.NgramDatabase(["abc#def", "abc,def"], n=1),
                ",",
                ["abc,def"],
                1.0,
            ),
            (
                [123, 456],
                sw_luadocs.extract.NgramDatabase(["123789456"], n=1),
                789,
                ["123789456"],
                1.0,
            ),
            (
                ["abc", "def", "ghi"],
                sw_luadocs.extract.NgramDatabase(["abc!", "def!", "ghi!"], n=1),
                "#",
                ["abc!", "def!", "ghi!"],
                0.5625,
            ),
            (
                ["abc", "def", "ghi"],
                sw_luadocs.extract.NgramDatabase(["abc!", "def", "ghi"], n=1),
                "#",
                ["abc!", "def", "ghi"],
                0.5625,
            ),
            (
                ["abc", "def", "ghi"],
                sw_luadocs.extract.NgramDatabase(["abc", "def!", "ghi"], n=1),
                "#",
                ["abc", "def!", "ghi"],
                0.5625,
            ),
            (
                ["abc", "def", "ghi"],
                sw_luadocs.extract.NgramDatabase(["abc", "def", "ghi!"], n=1),
                "#",
                ["abc", "def", "ghi!"],
                0.5625,
            ),
            (
                ["abc", "def", "ghi"],
                sw_luadocs.extract.NgramDatabase(["abc#def", "ghi"], n=1),
                "#",
                ["abc#def", "ghi"],
                1.0,
            ),
            (
                ["abc", "def", "ghi"],
                sw_luadocs.extract.NgramDatabase(["abc", "def#ghi"], n=1),
                "#",
                ["abc", "def#ghi"],
                1.0,
            ),
        ]:
            with self.subTest(
                ocr_txt_list=input_ocr_txt_list,
                ext_txt_db=input_ext_txt_db,
                sep=input_sep,
            ):
                actual_ext_txt_list, actual_score = sw_luadocs.extract.match_txt_pack(
                    input_ocr_txt_list, input_ext_txt_db, sep=input_sep
                )
                self.assertEqual(actual_ext_txt_list, expected_ext_txt_list)
                self.assertEqual(actual_score, expected_score)


class TestMatchFlatDocEachElem(unittest.TestCase):
    def test_invalid_type(self):
        for ocr_flatdoc, ext_txt_db in [
            ([None], sw_luadocs.extract.NgramDatabase(["a"])),
            ([], {}),
        ]:
            with self.subTest(ocr_flatdoc=ocr_flatdoc, ext_txt_db=ext_txt_db):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_flatdoc_eachelem(ocr_flatdoc, ext_txt_db)

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_db,
            expected_ext_flatdoc,
            expected_score,
        ) in [
            ([], sw_luadocs.extract.NgramDatabase(["a"], n=1), [], 1.0),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["h!", "b!", "c!"], n=1),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["h!", "b", "c"], n=1),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["h", "b!", "c"], n=1),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["h", "b", "c!"], n=1),
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc, ext_txt_db=input_ext_txt_db
            ):
                (
                    actual_ext_flatdoc,
                    actual_score,
                ) = sw_luadocs.extract.match_flatdoc_eachelem(
                    input_ocr_flatdoc, input_ext_txt_db
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)


class TestMatchFlatDocPackElem(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_flatdoc_packelem(
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a"]),
            )

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.match_flatdoc_packelem([], None)

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_db,
            input_sep,
            expected_ext_flatdoc,
            expected_score,
        ) in [
            ([], sw_luadocs.extract.NgramDatabase(["a"], n=1), "", [], 1.0),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
                sw_luadocs.extract.NgramDatabase(["ab", "bc"], n=1),
                "-",
                [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="head")],
                0.25,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")],
                sw_luadocs.extract.NgramDatabase(["ab", "bc"], n=1),
                "-",
                [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="body")],
                0.25,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")],
                sw_luadocs.extract.NgramDatabase(["ab", "bc"], n=1),
                "-",
                [sw_luadocs.flatdoc.FlatElem(txt="ab", kind="code")],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramDatabase(["a!", "b!", "c!"], n=1),
                "-",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b!", "a,b!", "a1b!"], n=1),
                "-",
                [sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="head")],
                0.5625,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b!", "a,b!", "a1b!"], n=1),
                ",",
                [sw_luadocs.flatdoc.FlatElem(txt="a,b!", kind="head")],
                0.5625,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b!", "a,b!", "a1b!"], n=1),
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="a1b!", kind="head")],
                0.5625,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="head")],
                sw_luadocs.extract.NgramDatabase(["a\nb!", "a", "b"], n=1),
                "\n",
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb!", kind="head")],
                0.5625,
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_db=input_ext_txt_db,
                sep=input_sep,
            ):
                (
                    actual_ext_flatdoc,
                    actual_score,
                ) = sw_luadocs.extract.match_flatdoc_packelem(
                    input_ocr_flatdoc, input_ext_txt_db, sep=input_sep
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)


class TestMatchFlatDocPackLine(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_flatdoc_packline(
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a"]),
            )

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.match_flatdoc_packline([], None)

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_db,
            input_sep,
            expected_ext_flatdoc,
            expected_score,
        ) in [
            ([], sw_luadocs.extract.NgramDatabase(["a"], n=1), "\n\n", [], 1.0),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")],
                sw_luadocs.extract.NgramDatabase(["b"], n=1),
                "\n",
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="code")],
                0.0,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="body")],
                sw_luadocs.extract.NgramDatabase(["d"], n=1),
                "\n",
                [sw_luadocs.flatdoc.FlatElem(txt="d", kind="body")],
                0.0,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="code")],
                sw_luadocs.extract.NgramDatabase(["a!", "b!"], n=1),
                "\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a\nb!"], n=1),
                "\n",
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb!", kind="code")],
                0.5625,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a!\n", "b!"], n=1),
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!\n", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a\n\nb!", "a,b!"], n=1),
                ",",
                [sw_luadocs.flatdoc.FlatElem(txt="a,b!", kind="code")],
                0.5625,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a\n\nb!", "a1b!"], n=1),
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="a1b!", kind="code")],
                0.5625,
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_db=input_ext_txt_db,
                sep=input_sep,
            ):
                (
                    actual_ext_flatdoc,
                    actual_score,
                ) = sw_luadocs.extract.match_flatdoc_packline(
                    input_ocr_flatdoc, input_ext_txt_db, sep=input_sep
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)


class TestMatchFlatDocMonoKind(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_flatdoc_monokind(
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramDatabase(["a"]),
            )

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.match_flatdoc_monokind([], {})

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_db,
            input_body_sep,
            input_code_sep,
            expected_ext_flatdoc,
            expected_score,
        ) in [
            ([], sw_luadocs.extract.NgramDatabase(["a"], n=1), "", "", [], 1.0),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="e\nf", kind="head"),
                ],
                sw_luadocs.extract.NgramDatabase(
                    [
                        "a",
                        "b=c",
                        "d=e",
                        "f",
                        "a\nb-c\nd-e\nf",
                        "a\nb!",
                        "c\nd!",
                        "e\nf!",
                    ],
                    n=1,
                ),
                "-",
                "=",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="e\nf!", kind="head"),
                ],
                0.5625,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="e\nf", kind="body"),
                ],
                sw_luadocs.extract.NgramDatabase(
                    [
                        "a",
                        "b=c",
                        "d=e",
                        "f",
                        "a\nb-c\nd-e\nf",
                        "a\nb!",
                        "c\nd!",
                        "e\nf!",
                    ],
                    n=1,
                ),
                "-",
                "=",
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb-c\nd-e\nf", kind="body")],
                1.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="e\nf", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(
                    [
                        "a",
                        "b=c",
                        "d=e",
                        "f",
                        "a\nb-c\nd-e\nf",
                        "a\nb!",
                        "c\nd!",
                        "e\nf!",
                    ],
                    n=1,
                ),
                "-",
                "=",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b=c", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="d=e", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="f", kind="code"),
                ],
                1.0,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
                sw_luadocs.extract.NgramDatabase(["a!"], n=1),
                "",
                "",
                [sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head")],
                0.25,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")],
                sw_luadocs.extract.NgramDatabase(["a!"], n=1),
                "",
                "",
                [sw_luadocs.flatdoc.FlatElem(txt="a!", kind="body")],
                0.25,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")],
                sw_luadocs.extract.NgramDatabase(["a!"], n=1),
                "",
                "",
                [sw_luadocs.flatdoc.FlatElem(txt="a!", kind="code")],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b", "a=b", "a1b", "a2b"], n=1),
                "-",
                "=",
                [sw_luadocs.flatdoc.FlatElem(txt="a-b", kind="body")],
                1.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b", "a=b", "a1b", "a2b"], n=1),
                1,
                2,
                [sw_luadocs.flatdoc.FlatElem(txt="a1b", kind="body")],
                1.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b", "a=b", "a1b", "a2b"], n=1),
                "-",
                "=",
                [sw_luadocs.flatdoc.FlatElem(txt="a=b", kind="code")],
                1.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b", "a=b", "a1b", "a2b"], n=1),
                1,
                2,
                [sw_luadocs.flatdoc.FlatElem(txt="a2b", kind="code")],
                1.0,
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_db=input_ext_txt_db,
                body_sep=input_body_sep,
                code_sep=input_code_sep,
            ):
                (
                    actual_ext_flatdoc,
                    actual_score,
                ) = sw_luadocs.extract.match_flatdoc_monokind(
                    input_ocr_flatdoc,
                    input_ext_txt_db,
                    body_sep=input_body_sep,
                    code_sep=input_code_sep,
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)


class TestMatchFlatDoc(unittest.TestCase):
    def test_invalid_type(self):
        for ocr_flatdoc, ext_txt_db, body_sep, code_sep in [
            ([None], sw_luadocs.extract.NgramDatabase(["a"]), "\n\n", "\n\n"),
            ([], {"a"}, "\n\n", "\n\n"),
        ]:
            with self.subTest(
                ocr_flatdoc=ocr_flatdoc,
                ext_txt_db=ext_txt_db,
                body_sep=body_sep,
                code_sep=code_sep,
            ):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_flatdoc(
                        ocr_flatdoc, ext_txt_db, body_sep=body_sep, code_sep=code_sep
                    )

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_db,
            input_body_sep,
            input_code_sep,
            expected_ext_flatdoc,
            expected_score,
        ) in [
            ([], sw_luadocs.extract.NgramDatabase(["a"], n=1), "", "", [], 1.0),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
                sw_luadocs.extract.NgramDatabase(["b"], n=1),
                "",
                "",
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="head")],
                0.0,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="body")],
                sw_luadocs.extract.NgramDatabase(["d"], n=1),
                "",
                "",
                [sw_luadocs.flatdoc.FlatElem(txt="d", kind="body")],
                0.0,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="e", kind="code")],
                sw_luadocs.extract.NgramDatabase(["f"], n=1),
                "",
                "",
                [sw_luadocs.flatdoc.FlatElem(txt="f", kind="code")],
                0.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramDatabase(["a!", "b!"], n=1),
                "\n\n",
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramDatabase(["a!", "b!"], n=1),
                "\n\n",
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a!", "b!"], n=1),
                "\n\n",
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b", "a=b", "a1b", "a2b"], n=1),
                "-",
                "=",
                [sw_luadocs.flatdoc.FlatElem(txt="a-b", kind="body")],
                1.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b", "a=b", "a1b", "a2b"], n=1),
                1,
                2,
                [sw_luadocs.flatdoc.FlatElem(txt="a1b", kind="body")],
                1.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b", "a=b", "a1b", "a2b"], n=1),
                "-",
                "=",
                [sw_luadocs.flatdoc.FlatElem(txt="a=b", kind="code")],
                1.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a-b", "a=b", "a1b", "a2b"], n=1),
                1,
                2,
                [sw_luadocs.flatdoc.FlatElem(txt="a2b", kind="code")],
                1.0,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramDatabase(["a\n\nb", "a!", "b!"], n=1),
                "\n\n",
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["a\n\nb", "a!", "b!"], n=1),
                "\n\n",
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramDatabase(["a\n\nb", "a!", "b!"], n=1),
                "\n\n",
                "\n\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["h!", "b", "c"], n=1),
                "",
                "",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["h", "b!", "c"], n=1),
                "",
                "",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                0.25,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramDatabase(["h", "b", "c!"], n=1),
                "",
                "",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_db=input_ext_txt_db,
                body_sep=input_body_sep,
                code_sep=input_code_sep,
            ):
                actual_ext_flatdoc, actual_score = sw_luadocs.extract.match_flatdoc(
                    input_ocr_flatdoc,
                    input_ext_txt_db,
                    body_sep=input_body_sep,
                    code_sep=input_code_sep,
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)
