import sw_luadocs.flatdoc
import unittest


class TestAsKind(unittest.TestCase):
    def test_validate_value_error(self):
        for v in "head", "body", "code":
            with self.subTest(v=v):
                kind = sw_luadocs.flatdoc.as_kind(v)
                self.assertEqual(kind, v)

    def test_validate_value_pass(self):
        with self.assertRaises(ValueError):
            sw_luadocs.flatdoc.as_kind("invalid")


class TestDocumentElemPostInit(unittest.TestCase):
    def test_validate_convert(self):
        flatelem = sw_luadocs.flatdoc.FlatElem(txt=0, kind="head")
        self.assertEqual(flatelem.txt, "0")
        self.assertEqual(flatelem.kind, "head")

    def test_validate_convert_kind(self):
        with self.assertRaises(ValueError):
            sw_luadocs.flatdoc.FlatElem(txt="", kind="invalid")


class TestAsFlatDoc(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.flatdoc.as_flatdoc([None])

    def test_main(self):
        for v in [
            [],
            [
                sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
            ],
        ]:
            with self.subTest(v=v):
                flatdoc = sw_luadocs.flatdoc.as_flatdoc(v)
                self.assertIs(type(flatdoc), list)
                self.assertEqual(flatdoc, v)


class TestAsFlatDocMonoKind(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.flatdoc.as_flatdoc_monokind([None])

    def test_validate_value_error(self):
        for v, kind in [
            ([], "invalid"),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="body"),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                None,
            ),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")], "body"),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")], "code"),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")], "head"),
        ]:
            with self.subTest(v=v, kind=kind):
                with self.assertRaises(ValueError):
                    sw_luadocs.flatdoc.as_flatdoc_monokind(v, kind=kind)

    def test_main(self):
        for v, kind in [
            ([], None),
            ([], "head"),
            ([], "body"),
            ([], "code"),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")], None),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")], None),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")], None),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")], "head"),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")], "body"),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")], "code"),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                ],
                "head",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                ],
                "body",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                ],
                "code",
            ),
        ]:
            with self.subTest(v=v, kind=kind):
                flatdoc = sw_luadocs.flatdoc.as_flatdoc_monokind(v, kind=kind)
                self.assertIs(type(flatdoc), list)
                self.assertEqual(flatdoc, v)


class TestSplitFlatDocByKind(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.flatdoc.split_flatdoc_by_kind([None])

    def test_main(self):
        for input_flatdoc, expected_flatdoc_monokind_list in [
            ([], []),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
                [[sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")]],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                [
                    [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
                    [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
                    [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
                ],
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="2", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="3", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="4", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="5", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="6", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="7", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="8", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                ],
                [
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="1", kind="head"),
                        sw_luadocs.flatdoc.FlatElem(txt="2", kind="head"),
                    ],
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="3", kind="body"),
                        sw_luadocs.flatdoc.FlatElem(txt="4", kind="body"),
                        sw_luadocs.flatdoc.FlatElem(txt="5", kind="body"),
                    ],
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="6", kind="code"),
                        sw_luadocs.flatdoc.FlatElem(txt="7", kind="code"),
                        sw_luadocs.flatdoc.FlatElem(txt="8", kind="code"),
                        sw_luadocs.flatdoc.FlatElem(txt="9", kind="code"),
                    ],
                ],
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc):
                actual_flatdoc_monokind_list = sw_luadocs.flatdoc.split_flatdoc_by_kind(
                    input_flatdoc
                )
                self.assertEqual(
                    actual_flatdoc_monokind_list, expected_flatdoc_monokind_list
                )


class TestMdlikeParserInit(unittest.TestCase):
    def test_main(self):
        p = sw_luadocs.flatdoc.MdlikeParser(0)
        self.assertEqual(p._line_list, ["0"])
        self.assertEqual(p._line_idx, 0)


class TestMdlikeParserCheckEOF(unittest.TestCase):
    def test_main(self):
        for input_line_list, input_line_idx, expected_result in [
            ([""], 0, False),
            ([""], 1, True),
            (["", ""], 1, False),
            (["", ""], 2, True),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_result = p.check_eof()
                self.assertEqual(actual_result, expected_result)


class TestMdlikeParserPeek(unittest.TestCase):
    def test_error(self):
        p = sw_luadocs.flatdoc.MdlikeParser("")
        p._line_list = [""]
        p._line_idx = 1
        with self.assertRaises(ValueError):
            p.peek()

    def test_pass(self):
        for input_line_list, input_line_idx, input_required, expected_line in [
            (["a", "b", "c"], 0, True, "a"),
            (["a", "b", "c"], 1, True, "b"),
            (["a", "b", "c"], 2, True, "c"),
            (["a", "b", "c"], 3, False, None),
        ]:
            with self.subTest(
                line_list=input_line_list,
                line_idx=input_line_idx,
                required=input_required,
            ):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_line = p.peek(required=input_required)
                self.assertEqual(actual_line, expected_line)


class TestMdlikeParserNext(unittest.TestCase):
    def test_main(self):
        for input_line_list, input_line_idx, expected_line_idx in [
            ([""], 0, 1),
            ([""], 1, 1),
            (["", ""], 1, 2),
            (["", ""], 2, 2),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                p.next()
                self.assertEqual(p._line_idx, expected_line_idx)


class TestMdlikeParserPop(unittest.TestCase):
    def test_error(self):
        p = sw_luadocs.flatdoc.MdlikeParser("")
        p._line_list = [""]
        p._line_idx = 1
        with self.assertRaises(ValueError):
            p.pop()

    def test_pass(self):
        for (
            input_line_list,
            input_line_idx,
            input_required,
            expected_line_idx,
            expected_line,
        ) in [
            (["a", "b", "c"], 0, True, 1, "a"),
            (["a", "b", "c"], 1, True, 2, "b"),
            (["a", "b", "c"], 2, True, 3, "c"),
            (["a", "b", "c"], 3, False, 3, None),
        ]:
            with self.subTest(
                line_list=input_line_list,
                line_idx=input_line_idx,
                required=input_required,
            ):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_line = p.pop(required=input_required)
                self.assertEqual(p._line_idx, expected_line_idx)
                self.assertEqual(actual_line, expected_line)


class TestMdlikeParserTransaction(unittest.TestCase):
    def test_pass(self):
        p = sw_luadocs.flatdoc.MdlikeParser("\n")
        p._line_idx = 0
        with p.transaction():
            p._line_idx = 1
        self.assertEqual(p._line_idx, 1)

    def test_rollback(self):
        p = sw_luadocs.flatdoc.MdlikeParser("\n")
        p._line_idx = 0
        with self.assertRaises(ValueError):
            with p.transaction():
                p._line_idx = 1
                raise ValueError
        self.assertEqual(p._line_idx, 0)

    def test_nested(self):
        p = sw_luadocs.flatdoc.MdlikeParser("\n")
        p._line_idx = 0
        with p.transaction():
            p._line_idx = 1
            with self.assertRaises(ValueError):
                with p.transaction():
                    p._line_idx = 2
                    raise ValueError
            self.assertEqual(p._line_idx, 1)
        self.assertEqual(p._line_idx, 1)


class TestMdlikeParserCheckBlank(unittest.TestCase):
    def test_main(self):
        for input_line_list, input_line_idx, expected_result in [
            (["a"], 0, False),
            ([""], 0, True),
            ([""], 1, False),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_result = p.check_blank()
                self.assertEqual(p._line_idx, input_line_idx)
                self.assertEqual(actual_result, expected_result)


class TestMdlikeParserCheckHead(unittest.TestCase):
    def test_main(self):
        for input_line_list, input_line_idx, expected_result in [
            (["# "], 0, True),
            (["# head"], 0, True),
            (["head"], 0, False),
            (["# "], 1, False),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_result = p.check_head()
                self.assertEqual(p._line_idx, input_line_idx)
                self.assertEqual(actual_result, expected_result)


class TestMdlikeParserCheckCode(unittest.TestCase):
    def test_main(self):
        for input_line_list, input_line_idx, expected_result in [
            (["```"], 0, True),
            (["code"], 0, False),
            (["```"], 1, False),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_result = p.check_code()
                self.assertEqual(p._line_idx, input_line_idx)
                self.assertEqual(actual_result, expected_result)


class TestMdlikeParserCheckBody(unittest.TestCase):
    def test_main(self):
        for input_line_list, input_line_idx, expected_result in [
            ([""], 0, False),
            (["# "], 0, False),
            (["```"], 0, False),
            (["body"], 0, True),
            (["body"], 1, False),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_result = p.check_body()
                self.assertEqual(p._line_idx, input_line_idx)
                self.assertEqual(actual_result, expected_result)


class TestMdlikeParserSkipBlank(unittest.TestCase):
    def test_main(self):
        for input_line_list, input_line_idx, expected_line_idx in [
            (["a"], 0, 0),
            (["", "", "a"], 0, 2),
            ([""], 1, 1),
            (["", ""], 0, 2),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                p.skip_blank()
                self.assertEqual(p._line_idx, expected_line_idx)


class TestMdlikeParserParseHead(unittest.TestCase):
    def test_error(self):
        for input_line_list, input_line_idx in [([""], 0), ([""], 1)]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                with self.assertRaises(ValueError):
                    p.parse_head()
                self.assertEqual(p._line_idx, input_line_idx)

    def test_pass(self):
        for input_line_list, input_line_idx, expected_line_idx, expected_flatelem in [
            (["# "], 0, 1, sw_luadocs.flatdoc.FlatElem(txt="", kind="head")),
            (["# a"], 0, 1, sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_flatelem = p.parse_head()
                self.assertEqual(p._line_idx, expected_line_idx)
                self.assertEqual(actual_flatelem, expected_flatelem)


class TestMdlikeParserParseBody(unittest.TestCase):
    def test_error(self):
        for input_line_list, input_line_idx in [([""], 0), ([""], 1)]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                with self.assertRaises(ValueError):
                    p.parse_body()
                self.assertEqual(p._line_idx, input_line_idx)

    def test_pass(self):
        for input_line_list, input_line_idx, expected_line_idx, expected_flatelem in [
            (
                ["a", "b", "c"],
                0,
                3,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="body"),
            ),
            (
                ["a\\", "b\\", "c\\"],
                0,
                3,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="body"),
            ),
            (
                ["a", "b", "c", "", "d", "e", "f"],
                0,
                3,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="body"),
            ),
            (
                ["a\\", "b\\", "c\\", "\\", "d\\", "e\\", "f"],
                0,
                7,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc\n\nd\ne\nf", kind="body"),
            ),
            (
                ["a", "b", "c", "# d", "e", "f"],
                0,
                3,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="body"),
            ),
            (
                ["a", "b", "c", "```", "d", "e", "f", "```"],
                0,
                3,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="body"),
            ),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_flatelem = p.parse_body()
                self.assertEqual(p._line_idx, expected_line_idx)
                self.assertEqual(actual_flatelem, expected_flatelem)


class TestMdlikeParserParseCode(unittest.TestCase):
    def test_error(self):
        for input_line_list, input_line_idx in [
            ([""], 0),
            ([""], 1),
            (["```", "a", "b", "c"], 0),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                with self.assertRaises(ValueError):
                    p.parse_code()
                self.assertEqual(p._line_idx, input_line_idx)

    def test_pass(self):
        for input_line_list, input_line_idx, expected_line_idx, expected_flatelem in [
            (
                ["```", "```", "d", "e", "f"],
                0,
                2,
                sw_luadocs.flatdoc.FlatElem(txt="", kind="code"),
            ),
            (
                ["```", "a", "b", "c", "```", "d", "e", "f"],
                0,
                5,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="code"),
            ),
            (
                ["```", "# a", "# b", "# c", "```", "d", "e", "f"],
                0,
                5,
                sw_luadocs.flatdoc.FlatElem(txt="# a\n# b\n# c", kind="code"),
            ),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_flatelem = p.parse_code()
                self.assertEqual(p._line_idx, expected_line_idx)
                self.assertEqual(actual_flatelem, expected_flatelem)


class TestMdlikeParserParseElem(unittest.TestCase):
    def test_error(self):
        p = sw_luadocs.flatdoc.MdlikeParser("")
        p._line_list = [""]
        p._line_idx = 0
        with self.assertRaises(ValueError):
            p.parse_elem()
        self.assertEqual(p._line_idx, 0)

    def test_pass(self):
        for input_line_list, input_line_idx, expected_line_idx, expected_flatelem in [
            (
                ["# a", "# b", "# c"],
                0,
                1,
                sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
            ),
            (
                ["a", "b", "c"],
                0,
                3,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="body"),
            ),
            (
                ["```", "a", "b", "c", "```"],
                0,
                5,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="code"),
            ),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list[:]
                p._line_idx = input_line_idx
                actual_flatelem = p.parse_elem()
                self.assertEqual(p._line_idx, expected_line_idx)
                self.assertEqual(actual_flatelem, expected_flatelem)


class TestMdlikeParserParse(unittest.TestCase):
    def test_error(self):
        p = sw_luadocs.flatdoc.MdlikeParser("")
        p._line_list = ["a", "b", "c", "```"]
        p._line_idx = 0
        with self.assertRaises(ValueError):
            p.parse()
        self.assertEqual(p._line_idx, 0)

    def test_pass(self):
        for input_line_list, input_line_idx, expected_line_idx, expected_flatdoc in [
            ([""], 0, 1, []),
            (
                ["# a", "b", "c", "d", "```", "e", "f", "g", "```"],
                0,
                9,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b\nc\nd", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="e\nf\ng", kind="code"),
                ],
            ),
            (
                ["", "# a", "", "b", "c", "d", "", "```", "e", "f", "g", "```", ""],
                0,
                13,
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b\nc\nd", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="e\nf\ng", kind="code"),
                ],
            ),
        ]:
            with self.subTest(line_list=input_line_list, line_idx=input_line_idx):
                p = sw_luadocs.flatdoc.MdlikeParser("")
                p._line_list = input_line_list
                p._line_idx = input_line_idx
                actual_flatdoc = p.parse()
                self.assertEqual(p._line_idx, expected_line_idx)
                self.assertEqual(actual_flatdoc, expected_flatdoc)


class TestParseMdlike(unittest.TestCase):
    def test_main(self):
        flatdoc = sw_luadocs.flatdoc.parse_mdlike(
            """\
# mdlike
mdlike is a simple markup language similar to Markdown. Its very simple specification
makes it easy to generate or parse mdlike format documents programmatically.

Since mdlike does not support the complex syntax of Markdown, including inline HTML, it
is not recommended to parse documents in mdlike format with the Markdown parser, and
vice versa.

```
import sw_luadocs.flatdoc

# To parse text in mdlike format, use sw_luadocs.flatdoc.parse_mdlike
flatdoc = sw_luadocs.flatdoc.parse_mdlike("mdlike string")
```
"""
        )
        self.assertEqual(
            flatdoc,
            [
                sw_luadocs.flatdoc.FlatElem(txt="mdlike", kind="head"),
                sw_luadocs.flatdoc.FlatElem(
                    txt="""\
mdlike is a simple markup language similar to Markdown. Its very simple specification
makes it easy to generate or parse mdlike format documents programmatically.\
""",
                    kind="body",
                ),
                sw_luadocs.flatdoc.FlatElem(
                    txt="""\
Since mdlike does not support the complex syntax of Markdown, including inline HTML, it
is not recommended to parse documents in mdlike format with the Markdown parser, and
vice versa.\
""",
                    kind="body",
                ),
                sw_luadocs.flatdoc.FlatElem(
                    txt="""\
import sw_luadocs.flatdoc

# To parse text in mdlike format, use sw_luadocs.flatdoc.parse_mdlike
flatdoc = sw_luadocs.flatdoc.parse_mdlike("mdlike string")\
""",
                    kind="code",
                ),
            ],
        )


class TestFormatMdlike(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(ValueError):
            sw_luadocs.flatdoc.format_mdlike(
                [sw_luadocs.flatdoc.FlatElem(txt="\n", kind="head")]
            )

    def test_pass(self):
        for input_flatdoc, expected_s in [
            ([], ""),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")], "# a\n"),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="body")], "a\\\n"),
            ([sw_luadocs.flatdoc.FlatElem(txt="a", kind="code")], "```\na\n```\n"),
            ([sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="body")], "a\\\nb\\\n"),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="head"),
                ],
                "# a\n\n# b\n\n# c\n",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="body"),
                ],
                "a\\\n\nb\\\n\nc\\\n",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                "```\na\n```\n\n```\nb\n```\n\n```\nc\n```\n",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c\nd", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="e\nf", kind="body"),
                ],
                "a\\\nb\\\n\nc\\\nd\\\n\ne\\\nf\\\n",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="mdlike", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="""\
mdlike is a simple markup language similar to Markdown. Its very simple specification
makes it easy to generate or parse mdlike format documents programmatically.\
""",
                        kind="body",
                    ),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="""\
Since mdlike does not support the complex syntax of Markdown, including inline HTML, it
is not recommended to parse documents in mdlike format with the Markdown parser, and
vice versa.\
""",
                        kind="body",
                    ),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="""\
import sw_luadocs.flatdoc

# To parse text in mdlike format, use sw_luadocs.flatdoc.parse_mdlike
flatdoc = sw_luadocs.flatdoc.parse_mdlike("mdlike string")\
""",
                        kind="code",
                    ),
                ],
                """\
# mdlike

mdlike is a simple markup language similar to Markdown. Its very simple specification\\
makes it easy to generate or parse mdlike format documents programmatically.\\

Since mdlike does not support the complex syntax of Markdown, including inline HTML, it\\
is not recommended to parse documents in mdlike format with the Markdown parser, and\\
vice versa.\\

```
import sw_luadocs.flatdoc

# To parse text in mdlike format, use sw_luadocs.flatdoc.parse_mdlike
flatdoc = sw_luadocs.flatdoc.parse_mdlike("mdlike string")
```
""",
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc):
                actual_s = sw_luadocs.flatdoc.format_mdlike(input_flatdoc)
                self.assertEqual(actual_s, expected_s)


class TestParse(unittest.TestCase):
    def test_invalid(self):
        for s in [
            "head:",
            "head \nbody:",
            ".... ",
            "\n",
            "\nhead ",
            "head \n\nbody ",
            "head \n\n",
        ]:
            with self.subTest(s=s):
                with self.assertRaises(ValueError):
                    sw_luadocs.flatdoc.parse(s)

    def test_main(self):
        for input_s, expected_flatdoc in [
            ("", []),
            ("head", [sw_luadocs.flatdoc.FlatElem(txt="", kind="head")]),
            ("body", [sw_luadocs.flatdoc.FlatElem(txt="", kind="body")]),
            ("code", [sw_luadocs.flatdoc.FlatElem(txt="", kind="code")]),
            ("head\n", [sw_luadocs.flatdoc.FlatElem(txt="", kind="head")]),
            ("head ", [sw_luadocs.flatdoc.FlatElem(txt="", kind="head")]),
            ("head abc", [sw_luadocs.flatdoc.FlatElem(txt="abc", kind="head")]),
            (
                "head\nbody\ncode\nhead \nhead abc\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="abc", kind="head"),
                ],
            ),
            ("head\n....", [sw_luadocs.flatdoc.FlatElem(txt="\n", kind="head")]),
            ("body\n....", [sw_luadocs.flatdoc.FlatElem(txt="\n", kind="body")]),
            ("code\n....", [sw_luadocs.flatdoc.FlatElem(txt="\n", kind="code")]),
            ("head\n....\n", [sw_luadocs.flatdoc.FlatElem(txt="\n", kind="head")]),
            ("head\n.... ", [sw_luadocs.flatdoc.FlatElem(txt="\n", kind="head")]),
            (
                "head abc\n.... def",
                [sw_luadocs.flatdoc.FlatElem(txt="abc\ndef", kind="head")],
            ),
            (
                "head abc\n....\n.... \n.... def\n.... ghi\n",
                [sw_luadocs.flatdoc.FlatElem(txt="abc\n\n\ndef\nghi", kind="head")],
            ),
            (
                "head head line 1\n.... head line 2\nbody body line 1\n.... body line 2\ncode code line 1\n.... code line 2",
                [
                    sw_luadocs.flatdoc.FlatElem(
                        txt="head line 1\nhead line 2", kind="head"
                    ),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="body line 1\nbody line 2", kind="body"
                    ),
                    sw_luadocs.flatdoc.FlatElem(
                        txt="code line 1\ncode line 2", kind="code"
                    ),
                ],
            ),
        ]:
            with self.subTest(s=input_s):
                actual_flatdoc = sw_luadocs.flatdoc.parse(input_s)
                self.assertEqual(actual_flatdoc, expected_flatdoc)
