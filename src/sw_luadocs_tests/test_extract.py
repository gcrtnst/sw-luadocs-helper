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


class TestGenerateRepackElemPatterns(unittest.TestCase):
    def test_main(self):
        for input_ocr_txt_list, input_sep, expected_pak_txt_list_list in [
            ([], "-", []),
            (["a"], "-", [["a"]]),
            (["a", "b"], "-", [["a", "b"], ["a-b"]]),
            (["a", "b"], ":", [["a", "b"], ["a:b"]]),
            ({1: None, 2: None}, 3, [["1", "2"], ["132"]]),
            (
                ["a", "b", "c"],
                "-",
                [["a", "b", "c"], ["a", "b-c"], ["a-b", "c"], ["a-b-c"]],
            ),
            (
                ["a", "b", "c", "d"],
                "-",
                [
                    ["a", "b", "c", "d"],
                    ["a", "b", "c-d"],
                    ["a", "b-c", "d"],
                    ["a", "b-c-d"],
                    ["a-b", "c", "d"],
                    ["a-b", "c-d"],
                    ["a-b-c", "d"],
                    ["a-b-c-d"],
                ],
            ),
        ]:
            with self.subTest(ocr_txt_list=input_ocr_txt_list, sep=input_sep):
                actual_pak_txt_list_list = list(
                    sw_luadocs.extract.generate_repack_elem_patterns(
                        input_ocr_txt_list, sep=input_sep
                    )
                )
                self.assertEqual(actual_pak_txt_list_list, expected_pak_txt_list_list)


class TestGenerateRepackLinePatterns(unittest.TestCase):
    def test_main(self):
        for input_ocr_txt_full, expected_pak_txt_list_list in [
            ("", []),
            ("\n", []),
            ("\n\n", []),
            ("a", [["a"]]),
            ("a\n", [["a\n"]]),
            ("a\n\n", [["a\n\n"]]),
            ("\na", [["\na"]]),
            ("\n\na", [["\n\na"]]),
            ("\na\n", [["\na\n"]]),
            ("\n\na\n\n", [["\n\na\n\n"]]),
            ("a\nb", [["a", "b"], ["a\nb"]]),
            ("\na\nb", [["\na", "b"], ["\na\nb"]]),
            ("\n\na\nb", [["\n\na", "b"], ["\n\na\nb"]]),
            ("a\n\nb", [["a", "\nb"], ["a\n", "b"], ["a\n\nb"]]),
            (
                "a\n\n\nb",
                [["a", "\n\nb"], ["a\n", "\nb"], ["a\n\n", "b"], ["a\n\n\nb"]],
            ),
            ("a\nb\n", [["a", "b\n"], ["a\nb\n"]]),
            ("a\nb\n\n", [["a", "b\n\n"], ["a\nb\n\n"]]),
            (
                "\n\na\n\n\nb\n\n",
                [
                    ["\n\na", "\n\nb\n\n"],
                    ["\n\na\n", "\nb\n\n"],
                    ["\n\na\n\n", "b\n\n"],
                    ["\n\na\n\n\nb\n\n"],
                ],
            ),
            (
                "\n\na\n\n\nb\n\n\nc\n\n",
                [
                    ["\n\na", "\n\nb", "\n\nc\n\n"],
                    ["\n\na", "\n\nb\n", "\nc\n\n"],
                    ["\n\na", "\n\nb\n\n", "c\n\n"],
                    ["\n\na", "\n\nb\n\n\nc\n\n"],
                    ["\n\na\n", "\nb", "\n\nc\n\n"],
                    ["\n\na\n", "\nb\n", "\nc\n\n"],
                    ["\n\na\n", "\nb\n\n", "c\n\n"],
                    ["\n\na\n", "\nb\n\n\nc\n\n"],
                    ["\n\na\n\n", "b", "\n\nc\n\n"],
                    ["\n\na\n\n", "b\n", "\nc\n\n"],
                    ["\n\na\n\n", "b\n\n", "c\n\n"],
                    ["\n\na\n\n", "b\n\n\nc\n\n"],
                    ["\n\na\n\n\nb", "\n\nc\n\n"],
                    ["\n\na\n\n\nb\n", "\nc\n\n"],
                    ["\n\na\n\n\nb\n\n", "c\n\n"],
                    ["\n\na\n\n\nb\n\n\nc\n\n"],
                ],
            ),
        ]:
            with self.subTest(ocr_txt_full=input_ocr_txt_full):
                actual_pak_txt_list_list = list(
                    sw_luadocs.extract.generate_repack_line_patterns(input_ocr_txt_full)
                )
                self.assertEqual(actual_pak_txt_list_list, expected_pak_txt_list_list)


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


class TestNgramSearchEngineInit(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.NgramSearchEngine(set(), n=0)

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
                actual_db = sw_luadocs.extract.NgramSearchEngine(
                    input_txt_set, n=input_n
                )
                self.assertEqual(actual_db._n, expected_db_n)
                self.assertEqual(actual_db._db, expected_db_db)


class TestNgramSearchEngineSearchAll(unittest.TestCase):
    def test_main(self):
        for input_self, input_txt, expected_result_list in [
            (sw_luadocs.extract.NgramSearchEngine([], n=1), "", []),
            (
                sw_luadocs.extract.NgramSearchEngine(
                    {"abc", "abd", "def", "bca", "cab"}, n=1
                ),
                "abc",
                [("abc", 1.0), ("bca", 1.0), ("cab", 1.0), ("abd", 0.5), ("def", 0.0)],
            ),
            (
                sw_luadocs.extract.NgramSearchEngine(
                    {"312", "231", "456", "124", "123"}, n=1
                ),
                "123",
                [("123", 1.0), ("231", 1.0), ("312", 1.0), ("124", 0.5), ("456", 0.0)],
            ),
            (
                sw_luadocs.extract.NgramSearchEngine(
                    {"abc", "abd", "def", "bca", "cab"}, n=3
                ),
                "abc",
                [("abc", 1.0), ("abd", 0.25), ("bca", 0.0), ("cab", 0.0), ("def", 0.0)],
            ),
        ]:
            with self.subTest(input_self=input_self, input_txt=input_txt):
                actual_result_list = input_self.search_all(input_txt)
                self.assertEqual(actual_result_list, expected_result_list)


class TestNgramSearchEngineSearchLucky(unittest.TestCase):
    def test_invalid_value(self):
        db = sw_luadocs.extract.NgramSearchEngine([], n=1)
        with self.assertRaises(ValueError):
            db.search_lucky("")

    def test_main(self):
        for input_self, input_txt, expected_txt, expected_score in [
            (
                sw_luadocs.extract.NgramSearchEngine(
                    {"abc", "abd", "def", "bca", "cab"}, n=1
                ),
                "abc",
                "abc",
                1.0,
            ),
            (
                sw_luadocs.extract.NgramSearchEngine(
                    {"312", "231", "456", "124", "123"}, n=1
                ),
                "312",
                "123",
                1.0,
            ),
            (
                sw_luadocs.extract.NgramSearchEngine({"abd", "def", "bca", "cab"}, n=3),
                "abc",
                "abd",
                0.25,
            ),
        ]:
            with self.subTest(input_self=input_self, input_txt=input_txt):
                actual_txt, actual_score = input_self.search_lucky(input_txt)
                self.assertEqual(actual_txt, expected_txt)
                self.assertEqual(actual_score, expected_score)


class TestAsCache(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.extract.as_cache([])

    def test_main(self):
        for input_v, expected_cache in [
            (None, {}),
            ({}, {}),
            ({"a": ("a", 1.0)}, {"a": ("a", 1.0)}),
        ]:
            with self.subTest(v=input_v):
                actual_cache = sw_luadocs.extract.as_cache(input_v)
                self.assertEqual(actual_cache, expected_cache)
                if input_v is not None:
                    self.assertIs(actual_cache, input_v)


class TestMatchTxtSingle(unittest.TestCase):
    def test_invalid_type(self):
        for ocr_txt, ext_txt_eng, cache in [
            ("", None, {}),
            ("", sw_luadocs.extract.NgramSearchEngine(["a"]), []),
        ]:
            with self.subTest(ocr_txt=ocr_txt, ext_txt_eng=ext_txt_eng, cache=cache):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_txt_single(
                        ocr_txt, ext_txt_eng, cache=cache
                    )

    def test_invalid_value(self):
        for ocr_txt, ext_txt_eng, cache in [
            ("a", sw_luadocs.extract.NgramSearchEngine(["a"], n=1), {"a": ("a", -0.1)}),
            ("a", sw_luadocs.extract.NgramSearchEngine(["a"], n=1), {"a": ("a", 1.1)}),
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                {"a": ("a", float("nan"))},
            ),
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                {"a": ("a", float("inf"))},
            ),
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                {"a": ("a", float("-inf"))},
            ),
        ]:
            with self.subTest(ocr_txt=ocr_txt, ext_txt_eng=ext_txt_eng, cache=cache):
                with self.assertRaises(ValueError):
                    sw_luadocs.extract.match_txt_single(
                        ocr_txt, ext_txt_eng, cache=cache
                    )

    def test_main(self):
        for (
            input_ocr_txt,
            input_ext_txt_eng,
            input_cache,
            expected_ext_txt,
            expected_score,
            expected_cache,
        ) in [
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                None,
                "a",
                1.0,
                None,
            ),
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!"], n=1),
                None,
                "a!",
                0.5,
                None,
            ),
            (
                1,
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!"], n=1),
                None,
                "1!",
                0.5,
                None,
            ),
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                {},
                "a",
                1,
                {"a": ("a", 1.0)},
            ),
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!"], n=1),
                {},
                "a!",
                0.5,
                {"a": ("a!", 0.5)},
            ),
            (
                1,
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!"], n=1),
                {},
                "1!",
                0.5,
                {"1": ("1!", 0.5)},
            ),
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!"], n=1),
                {"a": ("a?", 0.75)},
                "a?",
                0.75,
                {"a": ("a?", 0.75)},
            ),
            (
                1,
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!"], n=1),
                {"1": ("1?", 0.75)},
                "1?",
                0.75,
                {"1": ("1?", 0.75)},
            ),
            (
                "a",
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!"], n=1),
                {"a": (1, "0.75")},
                "1",
                0.75,
                {"a": ("1", 0.75)},
            ),
        ]:
            with self.subTest(
                ocr_txt=input_ocr_txt, ext_txt_eng=input_ext_txt_eng, cache=input_cache
            ):
                actual_cache = input_cache.copy() if input_cache is not None else None
                actual_ext_txt, actual_score = sw_luadocs.extract.match_txt_single(
                    input_ocr_txt, input_ext_txt_eng, cache=actual_cache
                )
                self.assertEqual(actual_ext_txt, expected_ext_txt)
                self.assertEqual(actual_score, expected_score)
                self.assertEqual(actual_cache, expected_cache)


class TestMatchTxtMultiple(unittest.TestCase):
    def test_invalid_type(self):
        for ocr_txt_list, ext_txt_eng, cache in [
            ([], None, {}),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"]), []),
        ]:
            with self.subTest(
                ocr_txt_list=ocr_txt_list, ext_txt_eng=ext_txt_eng, cache=cache
            ):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_txt_multiple(
                        ocr_txt_list, ext_txt_eng, cache=cache
                    )

    def test_main(self):
        for (
            input_ocr_txt_list,
            input_ext_txt_eng,
            input_cache,
            expected_ext_txt_list,
            expected_score,
            expected_cache,
        ) in [
            ([], sw_luadocs.extract.NgramSearchEngine(["a"], n=1), None, [], 1.0, None),
            (
                ["a"],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!"], n=1),
                None,
                ["a!"],
                0.5,
                None,
            ),
            (
                [1],
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!"], n=1),
                None,
                ["1!"],
                0.5,
                None,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                None,
                ["a!", "b!", "c!"],
                0.5,
                None,
            ),
            (
                [1, 2, 3],
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!", "3!"], n=1),
                None,
                ["1!", "2!", "3!"],
                0.5,
                None,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine(["a!?#", "b!", "c!"], n=1),
                None,
                ["a!?#", "b!", "c!"],
                0.25,
                None,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!?#", "c!"], n=1),
                None,
                ["a!", "b!?#", "c!"],
                0.25,
                None,
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!?#"], n=1),
                None,
                ["a!", "b!", "c!?#"],
                0.25,
                None,
            ),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"], n=1), {}, [], 1.0, {}),
            (
                ["a"],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!"], n=1),
                {},
                ["a!"],
                0.5,
                {"a": ("a!", 0.5)},
            ),
            (
                [1],
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!"], n=1),
                {},
                ["1!"],
                0.5,
                {"1": ("1!", 0.5)},
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                {},
                ["a!", "b!", "c!"],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                [1, 2, 3],
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!", "3!"], n=1),
                {},
                ["1!", "2!", "3!"],
                0.5,
                {"1": ("1!", 0.5), "2": ("2!", 0.5), "3": ("3!", 0.5)},
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine(["a!?#", "b!", "c!"], n=1),
                {},
                ["a!?#", "b!", "c!"],
                0.25,
                {"a": ("a!?#", 0.25), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!?#", "c!"], n=1),
                {},
                ["a!", "b!?#", "c!"],
                0.25,
                {"a": ("a!", 0.5), "b": ("b!?#", 0.25), "c": ("c!", 0.5)},
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!?#"], n=1),
                {},
                ["a!", "b!", "c!?#"],
                0.25,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!?#", 0.25)},
            ),
            (
                ["a"],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"a": ("a!", 0.5)},
                ["a!"],
                0.5,
                {"a": ("a!", 0.5)},
            ),
            (
                [1],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"1": ("1!", 0.5)},
                ["1!"],
                0.5,
                {"1": ("1!", 0.5)},
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
                ["a!", "b!", "c!"],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                [1, 2, 3],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"1": ("1!", 0.5), "2": ("2!", 0.5), "3": ("3!", 0.5)},
                ["1!", "2!", "3!"],
                0.5,
                {"1": ("1!", 0.5), "2": ("2!", 0.5), "3": ("3!", 0.5)},
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"a": ("a!?#", 0.25), "b": ("b!", 0.5), "c": ("c!", 0.5)},
                ["a!?#", "b!", "c!"],
                0.25,
                {"a": ("a!?#", 0.25), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"a": ("a!", 0.5), "b": ("b!?#", 0.25), "c": ("c!", 0.5)},
                ["a!", "b!?#", "c!"],
                0.25,
                {"a": ("a!", 0.5), "b": ("b!?#", 0.25), "c": ("c!", 0.5)},
            ),
            (
                ["a", "b", "c"],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!?#", 0.25)},
                ["a!", "b!", "c!?#"],
                0.25,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!?#", 0.25)},
            ),
        ]:
            with self.subTest(
                ocr_txt_list=input_ocr_txt_list,
                ext_txt_eng=input_ext_txt_eng,
                cache=input_cache,
            ):
                actual_cache = input_cache.copy() if input_cache is not None else None
                (
                    actual_ext_txt_list,
                    actual_score,
                ) = sw_luadocs.extract.match_txt_multiple(
                    input_ocr_txt_list, input_ext_txt_eng, cache=actual_cache
                )
                self.assertEqual(actual_ext_txt_list, expected_ext_txt_list)
                self.assertEqual(actual_score, expected_score)
                self.assertEqual(actual_cache, expected_cache)


class TestMatchTxtRepack(unittest.TestCase):
    def test_invalid_type(self):
        for pak_txt_list_iter, ext_txt_eng, cache in [
            ([], None, {}),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"]), []),
        ]:
            with self.subTest(
                pak_txt_list_iter=pak_txt_list_iter,
                ext_txt_eng=ext_txt_eng,
                cache=cache,
            ):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_txt_repack(
                        pak_txt_list_iter, ext_txt_eng, cache=cache
                    )

    def test_main(self):
        for (
            input_pak_txt_list_iter,
            input_ext_txt_eng,
            input_cache,
            expected_ext_txt_list,
            expected_score,
            expected_cache,
        ) in [
            ([], sw_luadocs.extract.NgramSearchEngine(["a"], n=1), None, [], 1.0, None),
            (
                [["a", "b", "c"]],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                None,
                ["a!", "b!", "c!"],
                0.5,
                None,
            ),
            (
                [[1, 2, 3]],
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!", "3!"], n=1),
                None,
                ["1!", "2!", "3!"],
                0.5,
                None,
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a!", "b!", "c!", "d!?#", "e!?#", "f!?#", "g!?#", "h!?#", "i!?#"],
                    n=1,
                ),
                None,
                ["a!", "b!", "c!"],
                0.5,
                None,
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a!?#", "b!?#", "c!?#", "d!", "e!", "f!", "g!?#", "h!?#", "i!?#"],
                    n=1,
                ),
                None,
                ["d!", "e!", "f!"],
                0.5,
                None,
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a!?#", "b!?#", "c!?#", "d!?#", "e!?#", "f!?#", "g!", "h!", "i!"],
                    n=1,
                ),
                None,
                ["g!", "h!", "i!"],
                0.5,
                None,
            ),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"], n=1), {}, [], 1.0, {}),
            (
                [["a", "b", "c"]],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                {},
                ["a!", "b!", "c!"],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                [[1, 2, 3]],
                sw_luadocs.extract.NgramSearchEngine(["1!", "2!", "3!"], n=1),
                {},
                ["1!", "2!", "3!"],
                0.5,
                {"1": ("1!", 0.5), "2": ("2!", 0.5), "3": ("3!", 0.5)},
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a!", "b!", "c!", "d!?#", "e!?#", "f!?#", "g!?#", "h!?#", "i!?#"],
                    n=1,
                ),
                {},
                ["a!", "b!", "c!"],
                0.5,
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "d": ("d!?#", 0.25),
                    "e": ("e!?#", 0.25),
                    "f": ("f!?#", 0.25),
                    "g": ("g!?#", 0.25),
                    "h": ("h!?#", 0.25),
                    "i": ("i!?#", 0.25),
                },
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a!?#", "b!?#", "c!?#", "d!", "e!", "f!", "g!?#", "h!?#", "i!?#"],
                    n=1,
                ),
                {},
                ["d!", "e!", "f!"],
                0.5,
                {
                    "a": ("a!?#", 0.25),
                    "b": ("b!?#", 0.25),
                    "c": ("c!?#", 0.25),
                    "d": ("d!", 0.5),
                    "e": ("e!", 0.5),
                    "f": ("f!", 0.5),
                    "g": ("g!?#", 0.25),
                    "h": ("h!?#", 0.25),
                    "i": ("i!?#", 0.25),
                },
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a!?#", "b!?#", "c!?#", "d!?#", "e!?#", "f!?#", "g!", "h!", "i!"],
                    n=1,
                ),
                {},
                ["g!", "h!", "i!"],
                0.5,
                {
                    "a": ("a!?#", 0.25),
                    "b": ("b!?#", 0.25),
                    "c": ("c!?#", 0.25),
                    "d": ("d!?#", 0.25),
                    "e": ("e!?#", 0.25),
                    "f": ("f!?#", 0.25),
                    "g": ("g!", 0.5),
                    "h": ("h!", 0.5),
                    "i": ("i!", 0.5),
                },
            ),
            (
                [["a", "b", "c"]],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
                ["a!", "b!", "c!"],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                [[1, 2, 3]],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"1": ("1!", 0.5), "2": ("2!", 0.5), "3": ("3!", 0.5)},
                ["1!", "2!", "3!"],
                0.5,
                {"1": ("1!", 0.5), "2": ("2!", 0.5), "3": ("3!", 0.5)},
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "d": ("d!?#", 0.25),
                    "e": ("e!?#", 0.25),
                    "f": ("f!?#", 0.25),
                    "g": ("g!?#", 0.25),
                    "h": ("h!?#", 0.25),
                    "i": ("i!?#", 0.25),
                },
                ["a!", "b!", "c!"],
                0.5,
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "d": ("d!?#", 0.25),
                    "e": ("e!?#", 0.25),
                    "f": ("f!?#", 0.25),
                    "g": ("g!?#", 0.25),
                    "h": ("h!?#", 0.25),
                    "i": ("i!?#", 0.25),
                },
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {
                    "a": ("a!?#", 0.25),
                    "b": ("b!?#", 0.25),
                    "c": ("c!?#", 0.25),
                    "d": ("d!", 0.5),
                    "e": ("e!", 0.5),
                    "f": ("f!", 0.5),
                    "g": ("g!?#", 0.25),
                    "h": ("h!?#", 0.25),
                    "i": ("i!?#", 0.25),
                },
                ["d!", "e!", "f!"],
                0.5,
                {
                    "a": ("a!?#", 0.25),
                    "b": ("b!?#", 0.25),
                    "c": ("c!?#", 0.25),
                    "d": ("d!", 0.5),
                    "e": ("e!", 0.5),
                    "f": ("f!", 0.5),
                    "g": ("g!?#", 0.25),
                    "h": ("h!?#", 0.25),
                    "i": ("i!?#", 0.25),
                },
            ),
            (
                [["a", "b", "c"], ["d", "e", "f"], ["g", "h", "i"]],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {
                    "a": ("a!?#", 0.25),
                    "b": ("b!?#", 0.25),
                    "c": ("c!?#", 0.25),
                    "d": ("d!?#", 0.25),
                    "e": ("e!?#", 0.25),
                    "f": ("f!?#", 0.25),
                    "g": ("g!", 0.5),
                    "h": ("h!", 0.5),
                    "i": ("i!", 0.5),
                },
                ["g!", "h!", "i!"],
                0.5,
                {
                    "a": ("a!?#", 0.25),
                    "b": ("b!?#", 0.25),
                    "c": ("c!?#", 0.25),
                    "d": ("d!?#", 0.25),
                    "e": ("e!?#", 0.25),
                    "f": ("f!?#", 0.25),
                    "g": ("g!", 0.5),
                    "h": ("h!", 0.5),
                    "i": ("i!", 0.5),
                },
            ),
        ]:
            with self.subTest(
                pak_txt_list_iter=input_pak_txt_list_iter,
                ext_txt_eng=input_ext_txt_eng,
                cache=input_cache,
            ):
                actual_cache = input_cache.copy() if input_cache is not None else None
                actual_ext_txt_list, actual_score = sw_luadocs.extract.match_txt_repack(
                    input_pak_txt_list_iter, input_ext_txt_eng, cache=actual_cache
                )
                self.assertEqual(actual_ext_txt_list, expected_ext_txt_list)
                self.assertEqual(actual_score, expected_score)
                self.assertEqual(actual_cache, expected_cache)


class TestMatchFlatDocEach(unittest.TestCase):
    def test_invalid_type(self):
        for ocr_flatdoc, ext_txt_eng, cache in [
            ([None], sw_luadocs.extract.NgramSearchEngine(["a"]), {}),
            ([], None, {}),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"]), []),
        ]:
            with self.subTest(
                ocr_flatdoc=ocr_flatdoc, ext_txt_eng=ext_txt_eng, cache=cache
            ):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_flatdoc_each(
                        ocr_flatdoc, ext_txt_eng, cache=cache
                    )

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_eng,
            input_cache,
            expected_ext_flatdoc,
            expected_score,
            expected_cache,
        ) in [
            ([], sw_luadocs.extract.NgramSearchEngine(["a"], n=1), None, [], 1.0, None),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["h!?#", "b!", "c!"], n=1),
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!?#", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!?#", "c!"], n=1),
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!?#", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!?#"], n=1),
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!?#", kind="code"),
                ],
                0.25,
                None,
            ),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"], n=1), {}, [], 1.0, {}),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                {"h": ("h!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                {"b": ("b!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                {"c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.5,
                {"h": ("h!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["h!?#", "b!", "c!"], n=1),
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!?#", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
                {"h": ("h!?#", 0.25), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!?#", "c!"], n=1),
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!?#", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
                {"h": ("h!", 0.5), "b": ("b!?#", 0.25), "c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!?#"], n=1),
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!?#", kind="code"),
                ],
                0.25,
                {"h": ("h!", 0.5), "b": ("b!", 0.5), "c": ("c!?#", 0.25)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"h": ("h!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                {"h": ("h!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"b": ("b!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                {"b": ("b!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"c": ("c!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                {"c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"h": ("h!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.5,
                {"h": ("h!", 0.5), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"h": ("h!?#", 0.25), "b": ("b!", 0.5), "c": ("c!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!?#", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
                {"h": ("h!?#", 0.25), "b": ("b!", 0.5), "c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"h": ("h!", 0.5), "b": ("b!?#", 0.25), "c": ("c!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!?#", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code"),
                ],
                0.25,
                {"h": ("h!", 0.5), "b": ("b!?#", 0.25), "c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                {"h": ("h!", 0.5), "b": ("b!", 0.5), "c": ("c!?#", 0.25)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!?#", kind="code"),
                ],
                0.25,
                {"h": ("h!", 0.5), "b": ("b!", 0.5), "c": ("c!?#", 0.25)},
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_eng=input_ext_txt_eng,
                cache=input_cache,
            ):
                actual_cache = input_cache.copy() if input_cache is not None else None
                (
                    actual_ext_flatdoc,
                    actual_score,
                ) = sw_luadocs.extract.match_flatdoc_each(
                    input_ocr_flatdoc, input_ext_txt_eng, cache=actual_cache
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)
                self.assertEqual(actual_cache, expected_cache)


class TestMatchFlatDocRepackElem(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_flatdoc_repack_elem(
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a"]),
            )

    def test_invalid_type(self):
        for ocr_flatdoc, ext_txt_eng, sep, cache in [
            ([None], sw_luadocs.extract.NgramSearchEngine(["a"]), "\n\n", {}),
            ([], None, "\n\n", {}),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"]), "\n\n", []),
        ]:
            with self.subTest(
                ocr_flatdoc=ocr_flatdoc, ext_txt_eng=ext_txt_eng, sep=sep, cache=cache
            ):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_flatdoc_repack_elem(
                        ocr_flatdoc, ext_txt_eng, sep=sep, cache=cache
                    )

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_eng,
            input_sep,
            input_cache,
            expected_ext_flatdoc,
            expected_score,
            expected_cache,
        ) in [
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "",
                None,
                [],
                1.0,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "-",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "-",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "-",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                "-",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a", "b-c!"], n=1),
                "-",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b-c!", kind="head"),
                ],
                0.75,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b!", "c"], n=1),
                "-",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                0.75,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b-c!?#$"], n=1),
                "-",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a-b-c!?#$", kind="head"),
                ],
                0.5,
                None,
            ),
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "",
                {},
                [],
                1.0,
                {},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "-",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                {"h": ("h!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "-",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                {"b": ("b!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "-",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                {"c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                "-",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a-b": ("a!", 0.25),
                    "b-c": ("b!", 0.25),
                    "a-b-c": ("a!", 0.2),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a", "b-c!"], n=1),
                "-",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b-c!", kind="head"),
                ],
                0.75,
                {
                    "a": ("a", 1.0),
                    "b": ("b-c!", 0.25),
                    "c": ("b-c!", 0.25),
                    "a-b": ("b-c!", 0.4),
                    "b-c": ("b-c!", 0.75),
                    "a-b-c": ("b-c!", 0.6),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b!", "c"], n=1),
                "-",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                0.75,
                {
                    "a": ("a-b!", 0.25),
                    "b": ("a-b!", 0.25),
                    "c": ("c", 1.0),
                    "a-b": ("a-b!", 0.75),
                    "b-c": ("a-b!", 0.4),
                    "a-b-c": ("a-b!", 0.6),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b-c!?#$"], n=1),
                "-",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a-b-c!?#$", kind="head"),
                ],
                0.5,
                {
                    "a": ("a-b-c!?#$", 0.125),
                    "b": ("a-b-c!?#$", 0.125),
                    "c": ("a-b-c!?#$", 0.125),
                    "a-b": ("a-b-c!?#$", 0.375),
                    "b-c": ("a-b-c!?#$", 0.375),
                    "a-b-c": ("a-b-c!?#$", 0.5),
                },
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {"h": ("h!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                {"h": ("h!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {"b": ("b!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                {"b": ("b!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {"c": ("c!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                {"c": ("c!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a-b": ("a!", 0.25),
                    "b-c": ("b!", 0.25),
                    "a-b-c": ("a!", 0.2),
                },
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a-b": ("a!", 0.25),
                    "b-c": ("b!", 0.25),
                    "a-b-c": ("a!", 0.2),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {
                    "a": ("a", 1.0),
                    "b": ("b-c!", 0.25),
                    "c": ("b-c!", 0.25),
                    "a-b": ("b-c!", 0.4),
                    "b-c": ("b-c!", 0.75),
                    "a-b-c": ("b-c!", 0.6),
                },
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b-c!", kind="head"),
                ],
                0.75,
                {
                    "a": ("a", 1.0),
                    "b": ("b-c!", 0.25),
                    "c": ("b-c!", 0.25),
                    "a-b": ("b-c!", 0.4),
                    "b-c": ("b-c!", 0.75),
                    "a-b-c": ("b-c!", 0.6),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {
                    "a": ("a-b!", 0.25),
                    "b": ("a-b!", 0.25),
                    "c": ("c", 1.0),
                    "a-b": ("a-b!", 0.75),
                    "b-c": ("a-b!", 0.4),
                    "a-b-c": ("a-b!", 0.6),
                },
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                0.75,
                {
                    "a": ("a-b!", 0.25),
                    "b": ("a-b!", 0.25),
                    "c": ("c", 1.0),
                    "a-b": ("a-b!", 0.75),
                    "b-c": ("a-b!", 0.4),
                    "a-b-c": ("a-b!", 0.6),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {
                    "a": ("a-b-c!?#$", 0.125),
                    "b": ("a-b-c!?#$", 0.125),
                    "c": ("a-b-c!?#$", 0.125),
                    "a-b": ("a-b-c!?#$", 0.375),
                    "b-c": ("a-b-c!?#$", 0.375),
                    "a-b-c": ("a-b-c!?#$", 0.5),
                },
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a-b-c!?#$", kind="head"),
                ],
                0.5,
                {
                    "a": ("a-b-c!?#$", 0.125),
                    "b": ("a-b-c!?#$", 0.125),
                    "c": ("a-b-c!?#$", 0.125),
                    "a-b": ("a-b-c!?#$", 0.375),
                    "b-c": ("a-b-c!?#$", 0.375),
                    "a-b-c": ("a-b-c!?#$", 0.5),
                },
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_eng=input_ext_txt_eng,
                sep=input_sep,
            ):
                actual_cache = input_cache.copy() if input_cache is not None else None
                (
                    actual_ext_flatdoc,
                    actual_score,
                ) = sw_luadocs.extract.match_flatdoc_repack_elem(
                    input_ocr_flatdoc,
                    input_ext_txt_eng,
                    sep=input_sep,
                    cache=actual_cache,
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)
                self.assertEqual(actual_cache, expected_cache)


class TestMatchFlatDocRepackLine(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_flatdoc_repack_line(
                [
                    sw_luadocs.flatdoc.FlatElem(txt="h", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a"]),
            )

    def test_invalid_type(self):
        for ocr_flatdoc, ext_txt_eng, sep, cache in [
            ([None], sw_luadocs.extract.NgramSearchEngine(["a"]), "\n\n", {}),
            ([], None, "\n\n", {}),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"]), "\n\n", []),
        ]:
            with self.subTest(
                ocr_flatdoc=ocr_flatdoc, ext_txt_eng=ext_txt_eng, sep=sep, cache=cache
            ):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_flatdoc_repack_line(
                        ocr_flatdoc, ext_txt_eng, sep=sep, cache=cache
                    )

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_eng,
            input_sep,
            input_cache,
            expected_ext_flatdoc,
            expected_score,
            expected_cache,
        ) in [
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "",
                None,
                [],
                1.0,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="head")],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                "-",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                "\n",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b-c!?#$"], n=1),
                "-",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a-b-c!?#$", kind="head")],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a1b1c!?#$"], n=1),
                1,
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a1b1c!?#$", kind="head")],
                0.5,
                None,
            ),
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "",
                {},
                [],
                1.0,
                {},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                {"h": ("h!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                {"b": ("b!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine(["h!", "b!", "c!"], n=1),
                "",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                {"c": ("c!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="head")],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                "-",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a\nb": ("a!", 0.25),
                    "b\nc": ("b!", 0.25),
                    "a\nb\nc": ("a!", 0.2),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "c!"], n=1),
                "\n",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a\nb": ("a!", 0.25),
                    "b\nc": ("b!", 0.25),
                    "a\nb\nc": ("a!", 0.2),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b-c!?#$"], n=1),
                "-",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a-b-c!?#$", kind="head")],
                0.5,
                {"a-b-c": ("a-b-c!?#$", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a1b1c!?#$"], n=1),
                1,
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a1b1c!?#$", kind="head")],
                0.5,
                {"a1b1c": ("a1b1c!?#$", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "",
                {"h": ("h!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="h!", kind="head")],
                0.5,
                {"h": ("h!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "",
                {"b": ("b!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body")],
                0.5,
                {"b": ("b!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "",
                {"c": ("c!", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="c!", kind="code")],
                0.5,
                {"c": ("c!", 0.5)},
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="head")],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a\nb": ("a!", 0.25),
                    "b\nc": ("b!", 0.25),
                    "a\nb\nc": ("a!", 0.2),
                },
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a\nb": ("a!", 0.25),
                    "b\nc": ("b!", 0.25),
                    "a\nb\nc": ("a!", 0.2),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "\n",
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a\nb": ("a!", 0.25),
                    "b\nc": ("b!", 0.25),
                    "a\nb\nc": ("a!", 0.2),
                },
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c!", kind="head"),
                ],
                0.5,
                {
                    "a": ("a!", 0.5),
                    "b": ("b!", 0.5),
                    "c": ("c!", 0.5),
                    "a\nb": ("a!", 0.25),
                    "b\nc": ("b!", 0.25),
                    "a\nb\nc": ("a!", 0.2),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                {"a-b-c": ("a-b-c!?#$", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="a-b-c!?#$", kind="head")],
                0.5,
                {"a-b-c": ("a-b-c!?#$", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                1,
                {"a1b1c": ("a1b1c!?#$", 0.5)},
                [sw_luadocs.flatdoc.FlatElem(txt="a1b1c!?#$", kind="head")],
                0.5,
                {"a1b1c": ("a1b1c!?#$", 0.5)},
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_eng=input_ext_txt_eng,
                sep=input_sep,
            ):
                actual_cache = input_cache.copy() if input_cache is not None else None
                (
                    actual_ext_flatdoc,
                    actual_score,
                ) = sw_luadocs.extract.match_flatdoc_repack_line(
                    input_ocr_flatdoc,
                    input_ext_txt_eng,
                    sep=input_sep,
                    cache=actual_cache,
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)
                self.assertEqual(actual_cache, expected_cache)


class TestMatchFlatDocMonoKind(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.extract.match_flatdoc_monokind(
                [
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a"]),
            )

    def test_invalid_type(self):
        for ocr_flatdoc, ext_txt_eng, body_sep, code_sep, cache in [
            ([None], sw_luadocs.extract.NgramSearchEngine(["a"]), "\n\n", "\n\n", {}),
            ([], None, "\n\n", "\n\n", {}),
            ([], sw_luadocs.extract.NgramSearchEngine(["a"]), "\n\n", "\n\n", []),
        ]:
            with self.subTest(
                ocr_flatdoc=ocr_flatdoc,
                ext_txt_eng=ext_txt_eng,
                body_sep=body_sep,
                code_sep=code_sep,
                cache=cache,
            ):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_flatdoc_monokind(
                        ocr_flatdoc,
                        ext_txt_eng,
                        body_sep=body_sep,
                        code_sep=code_sep,
                        cache=cache,
                    )

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_eng,
            input_body_sep,
            input_code_sep,
            input_cache,
            expected_ext_flatdoc,
            expected_score,
            expected_cache,
        ) in [
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "\n\n",
                "\n\n",
                None,
                [],
                1.0,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!"], n=1),
                "-",
                "-",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a\nb\nc\nd!?#", "a", "b", "c", "d"], n=1
                ),
                "\n",
                "\n",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc\nd!?#", kind="body")],
                0.625,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b!", "a=b!"], n=1),
                "-",
                "=",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="body")],
                0.75,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a\nb\nc\nd!?#", "a", "b", "c", "d"], n=1
                ),
                "\n",
                "\n",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="d", kind="code"),
                ],
                1.0,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b!", "a=b!"], n=1),
                "-",
                "=",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a=b!", kind="code")],
                0.75,
                None,
            ),
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "\n\n",
                "\n\n",
                {},
                [],
                1.0,
                {},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!"], n=1),
                "-",
                "-",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a\nb\nc\nd!?#", "a", "b", "c", "d"], n=1
                ),
                "\n",
                "\n",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc\nd!?#", kind="body")],
                0.625,
                {
                    "a\nb": ("a\nb\nc\nd!?#", 0.375),
                    "c\nd": ("a\nb\nc\nd!?#", 0.375),
                    "a\nb\nc\nd": ("a\nb\nc\nd!?#", 0.625),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b!", "a=b!"], n=1),
                "-",
                "=",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="body")],
                0.75,
                {"a": ("a-b!", 0.25), "b": ("a-b!", 0.25), "a-b": ("a-b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(
                    ["a\nb\nc\nd!?#", "a", "b", "c", "d"], n=1
                ),
                "\n",
                "\n",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="d", kind="code"),
                ],
                1.0,
                {
                    "a": ("a", 1.0),
                    "b": ("b", 1.0),
                    "c": ("c", 1.0),
                    "d": ("d", 1.0),
                    "a\nb": ("a\nb\nc\nd!?#", 0.375),
                    "b\nc": ("a\nb\nc\nd!?#", 0.375),
                    "c\nd": ("a\nb\nc\nd!?#", 0.375),
                    "a\nb\nc": ("a\nb\nc\nd!?#", 0.5),
                    "b\nc\nd": ("a\nb\nc\nd!?#", 0.5),
                    "a\nb\nc\nd": ("a\nb\nc\nd!?#", 0.625),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a-b!", "a=b!"], n=1),
                "-",
                "=",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a=b!", kind="code")],
                0.75,
                {"a=b": ("a=b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "-",
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "\n",
                "\n",
                {
                    "a\nb": ("a\nb\nc\nd!?#", 0.375),
                    "c\nd": ("a\nb\nc\nd!?#", 0.375),
                    "a\nb\nc\nd": ("a\nb\nc\nd!?#", 0.625),
                },
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc\nd!?#", kind="body")],
                0.625,
                {
                    "a\nb": ("a\nb\nc\nd!?#", 0.375),
                    "c\nd": ("a\nb\nc\nd!?#", 0.375),
                    "a\nb\nc\nd": ("a\nb\nc\nd!?#", 0.625),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a": ("a-b!", 0.25), "b": ("a-b!", 0.25), "a-b": ("a-b!", 0.75)},
                [sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="body")],
                0.75,
                {"a": ("a-b!", 0.25), "b": ("a-b!", 0.25), "a-b": ("a-b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "\n",
                "\n",
                {
                    "a": ("a", 1.0),
                    "b": ("b", 1.0),
                    "c": ("c", 1.0),
                    "d": ("d", 1.0),
                    "a\nb": ("a\nb\nc\nd!?#", 0.375),
                    "b\nc": ("a\nb\nc\nd!?#", 0.375),
                    "c\nd": ("a\nb\nc\nd!?#", 0.375),
                    "a\nb\nc": ("a\nb\nc\nd!?#", 0.5),
                    "b\nc\nd": ("a\nb\nc\nd!?#", 0.5),
                    "a\nb\nc\nd": ("a\nb\nc\nd!?#", 0.625),
                },
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="d", kind="code"),
                ],
                1.0,
                {
                    "a": ("a", 1.0),
                    "b": ("b", 1.0),
                    "c": ("c", 1.0),
                    "d": ("d", 1.0),
                    "a\nb": ("a\nb\nc\nd!?#", 0.375),
                    "b\nc": ("a\nb\nc\nd!?#", 0.375),
                    "c\nd": ("a\nb\nc\nd!?#", 0.375),
                    "a\nb\nc": ("a\nb\nc\nd!?#", 0.5),
                    "b\nc\nd": ("a\nb\nc\nd!?#", 0.5),
                    "a\nb\nc\nd": ("a\nb\nc\nd!?#", 0.625),
                },
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a=b": ("a=b!", 0.75)},
                [sw_luadocs.flatdoc.FlatElem(txt="a=b!", kind="code")],
                0.75,
                {"a=b": ("a=b!", 0.75)},
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_eng=input_ext_txt_eng,
                body_sep=input_body_sep,
                code_sep=input_code_sep,
                cache=input_cache,
            ):
                actual_cache = input_cache.copy() if input_cache is not None else None
                (
                    actual_ext_flatdoc,
                    actual_score,
                ) = sw_luadocs.extract.match_flatdoc_monokind(
                    input_ocr_flatdoc,
                    input_ext_txt_eng,
                    body_sep=input_body_sep,
                    code_sep=input_code_sep,
                    cache=actual_cache,
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)
                self.assertEqual(actual_cache, expected_cache)


class TestMatchFlatDoc(unittest.TestCase):
    def test_invalid_type(self):
        for ocr_flatdoc, ext_txt_eng, body_sep, code_sep, cache in [
            (
                [None],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "\n\n",
                "\n\n",
                {},
            ),
            (
                [],
                None,
                "\n\n",
                "\n\n",
                {},
            ),
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "\n\n",
                "\n\n",
                [],
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=ocr_flatdoc,
                ext_txt_eng=ext_txt_eng,
                body_sep=body_sep,
                code_sep=code_sep,
                cache=cache,
            ):
                with self.assertRaises(TypeError):
                    sw_luadocs.extract.match_flatdoc(
                        ocr_flatdoc,
                        ext_txt_eng,
                        body_sep=body_sep,
                        code_sep=code_sep,
                        cache=cache,
                    )

    def test_main(self):
        for (
            input_ocr_flatdoc,
            input_ext_txt_eng,
            input_body_sep,
            input_code_sep,
            input_cache,
            expected_ext_flatdoc,
            expected_score,
            expected_cache,
        ) in [
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "",
                "",
                None,
                [],
                1.0,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="body")],
                0.75,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a=b!", kind="code")],
                0.75,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a1b!", "a2b!"], n=1),
                1,
                2,
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a1b!", kind="body")],
                0.75,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a1b!", "a2b!"], n=1),
                1,
                2,
                None,
                [sw_luadocs.flatdoc.FlatElem(txt="a2b!", kind="code")],
                0.75,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="code"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!?#"], n=1),
                "-",
                "=",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!?#", kind="head"),
                ],
                0.25,
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!?#", "b!"], n=1),
                "-",
                "=",
                None,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!?#", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.25,
                None,
            ),
            (
                [],
                sw_luadocs.extract.NgramSearchEngine(["a"], n=1),
                "",
                "",
                {},
                [],
                1.0,
                {},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="body")],
                0.75,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "a-b": ("a-b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a=b!", kind="code")],
                0.75,
                {"a=b": ("a=b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a1b!", "a2b!"], n=1),
                1,
                2,
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a1b!", kind="body")],
                0.75,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "a1b": ("a1b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a1b!", "a2b!"], n=1),
                1,
                2,
                {},
                [sw_luadocs.flatdoc.FlatElem(txt="a2b!", kind="code")],
                0.75,
                {"a2b": ("a2b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="code"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!", "a-b!", "a=b!"], n=1),
                "-",
                "=",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!", "b!?#"], n=1),
                "-",
                "=",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!?#", kind="head"),
                ],
                0.25,
                {"a": ("a!", 0.5), "b": ("b!?#", 0.25)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine(["a!?#", "b!"], n=1),
                "-",
                "=",
                {},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!?#", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.25,
                {"a": ("a!?#", 0.25), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "a-b": ("a-b!", 0.75)},
                [sw_luadocs.flatdoc.FlatElem(txt="a-b!", kind="body")],
                0.75,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "a-b": ("a-b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a=b": ("a=b!", 0.75)},
                [sw_luadocs.flatdoc.FlatElem(txt="a=b!", kind="code")],
                0.75,
                {"a=b": ("a=b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                1,
                2,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "a1b": ("a1b!", 0.75)},
                [sw_luadocs.flatdoc.FlatElem(txt="a1b!", kind="body")],
                0.75,
                {"a": ("a!", 0.5), "b": ("b!", 0.5), "a1b": ("a1b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                1,
                2,
                {"a2b": ("a2b!", 0.75)},
                [sw_luadocs.flatdoc.FlatElem(txt="a2b!", kind="code")],
                0.75,
                {"a2b": ("a2b!", 0.75)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="body"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="code"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.5,
                {"a": ("a!", 0.5), "b": ("b!", 0.5)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a": ("a!", 0.5), "b": ("b!?#", 0.25)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!?#", kind="head"),
                ],
                0.25,
                {"a": ("a!", 0.5), "b": ("b!?#", 0.25)},
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                ],
                sw_luadocs.extract.NgramSearchEngine([], n=1),
                "-",
                "=",
                {"a": ("a!?#", 0.25), "b": ("b!", 0.5)},
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a!?#", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b!", kind="head"),
                ],
                0.25,
                {"a": ("a!?#", 0.25), "b": ("b!", 0.5)},
            ),
        ]:
            with self.subTest(
                ocr_flatdoc=input_ocr_flatdoc,
                ext_txt_eng=input_ext_txt_eng,
                body_sep=input_body_sep,
                code_sep=input_code_sep,
                cache=input_cache,
            ):
                actual_cache = input_cache.copy() if input_cache is not None else None
                actual_ext_flatdoc, actual_score = sw_luadocs.extract.match_flatdoc(
                    input_ocr_flatdoc,
                    input_ext_txt_eng,
                    body_sep=input_body_sep,
                    code_sep=input_code_sep,
                    cache=actual_cache,
                )
                self.assertEqual(actual_ext_flatdoc, expected_ext_flatdoc)
                self.assertEqual(actual_score, expected_score)
                self.assertEqual(actual_cache, expected_cache)
