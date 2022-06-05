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
            sw_luadocs.flatdoc.as_kind("invliad")


class TestDocumentElemPostInit(unittest.TestCase):
    def test_validate_convert(self):
        flatelem = sw_luadocs.flatdoc.FlatElem(txt=0, kind="head")
        self.assertEqual(flatelem.txt, "0")
        self.assertEqual(flatelem.kind, "head")

    def test_validate_convert_kind(self):
        with self.assertRaises(ValueError):
            sw_luadocs.flatdoc.FlatElem(txt="", kind="invalid")


class TestLoadsElem(unittest.TestCase):
    def test_validate_value_error(self):
        for s in ["", "[", "]", "\n[head]", "[head]txt"]:
            with self.subTest(s=s):
                with self.assertRaises(ValueError):
                    sw_luadocs.flatdoc.loads_elem(s)

    def test_kind(self):
        for s, kind in [
            ("[head]", "head"),
            ("[body]", "body"),
            ("[code]", "code"),
            ("[head]\n[body]", "head"),
        ]:
            with self.subTest(s=s):
                flatelem = sw_luadocs.flatdoc.loads_elem(s)
                self.assertEqual(flatelem.kind, kind)

    def test_txt(self):
        for s, txt in [
            ("[body]", ""),
            ("[body]\n", ""),
            ("[body]\n\n", ""),
            ("[body]\ntxt", "txt"),
            ("[body]\n\ntxt", "\ntxt"),
            ("[body]\n\ntxt\n", "\ntxt"),
            ("[body]\n\na\n\nb\n\nc\n", "\na\n\nb\n\nc"),
        ]:
            with self.subTest(s=s):
                flatelem = sw_luadocs.flatdoc.loads_elem(s)
                self.assertEqual(flatelem.txt, txt)


class TestDumpsElem(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.flatdoc.dumps_elem(None)

    def test_validate_value_error(self):
        with self.assertRaises(ValueError):
            sw_luadocs.flatdoc.dumps_elem(
                sw_luadocs.flatdoc.FlatElem(txt="\n", kind="code")
            )

    def test_newline(self):
        for input_flatelem, expected_s in [
            (sw_luadocs.flatdoc.FlatElem(txt="", kind="body"), "[body]\n"),
            (sw_luadocs.flatdoc.FlatElem(txt="txt", kind="body"), "[body]\ntxt\n"),
            (
                sw_luadocs.flatdoc.FlatElem(txt="\na\n\nb\n\nc", kind="body"),
                "[body]\n\na\n\nb\n\nc\n",
            ),
        ]:
            with self.subTest(flatelem=input_flatelem):
                actual_s = sw_luadocs.flatdoc.dumps_elem(input_flatelem)
                self.assertEqual(actual_s, expected_s)


class TestLoads(unittest.TestCase):
    def test_validate_value_error(self):
        for s in ["[", "]", "[head]txt", "txt\n[head]", "\ntxt\n\n[head]"]:
            with self.subTest(s=s):
                with self.assertRaises(ValueError):
                    sw_luadocs.flatdoc.loads(s)

    def test_loads(self):
        for input_s, expected_flatdoc in [
            ("", []),
            ("\n\n", []),
            ("[head]", [sw_luadocs.flatdoc.FlatElem(txt="", kind="head")]),
            ("[body]", [sw_luadocs.flatdoc.FlatElem(txt="", kind="body")]),
            ("[code]", [sw_luadocs.flatdoc.FlatElem(txt="", kind="code")]),
            ("\n\n[head]", [sw_luadocs.flatdoc.FlatElem(txt="", kind="head")]),
            (
                "[head]\n[body]\n[code]",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="code"),
                ],
            ),
            (
                "\n\n[head]\na\n[body]\nb\n[code]\nc\n",
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
            ),
        ]:
            with self.subTest(s=input_s):
                actual_flatdoc = sw_luadocs.flatdoc.loads(input_s)
                self.assertEqual(actual_flatdoc, expected_flatdoc)


class TestDumps(unittest.TestCase):
    def test_validate_value_error(self):
        with self.assertRaises(ValueError):
            sw_luadocs.flatdoc.dumps(
                [sw_luadocs.flatdoc.FlatElem(txt="[body]", kind="body")]
            )

    def test_dumps(self):
        for input_flatdoc, expected_s in [
            ([], ""),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
                ],
                "[head]\na\n\n[body]\nb\n\n[code]\nc\n",
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc):
                actual_s = sw_luadocs.flatdoc.dumps(input_flatdoc)
                self.assertEqual(actual_s, expected_s)


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
                ["a", "b", "c", "", "d", "e", "f"],
                0,
                3,
                sw_luadocs.flatdoc.FlatElem(txt="a\nb\nc", kind="body"),
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
