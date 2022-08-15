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


class TestFormat(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.flatdoc.format([None])

    def test_main(self):
        for input_flatdoc, expected_s in [
            ([], ""),
            ([sw_luadocs.flatdoc.FlatElem(txt="", kind="head")], "head \n"),
            ([sw_luadocs.flatdoc.FlatElem(txt="", kind="body")], "body \n"),
            ([sw_luadocs.flatdoc.FlatElem(txt="", kind="code")], "code \n"),
            ([sw_luadocs.flatdoc.FlatElem(txt="abc", kind="head")], "head abc\n"),
            ([sw_luadocs.flatdoc.FlatElem(txt="\n", kind="head")], "head \n.... \n"),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="abc\ndef\nghi", kind="head")],
                "head abc\n.... def\n.... ghi\n",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="head", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="head\nhead\n", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="body", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="body\nbody\n", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="code", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="code\ncode\n", kind="code"),
                ],
                "head \nhead head\nhead head\n.... head\n.... \nbody \nbody body\nbody body\n.... body\n.... \ncode \ncode code\ncode code\n.... code\n.... \n",
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc):
                actual_s = sw_luadocs.flatdoc.format(input_flatdoc)
                self.assertEqual(actual_s, expected_s)


class TestExporterExport(unittest.TestCase):
    def test_invalid_notimplemented(self):
        for (
            _head_prefix,
            _head_suffix,
            _body_prefix,
            _body_suffix,
            _code_prefix,
            _code_suffix,
        ) in [
            (None, "hs", "bp", "bs", "cp", "cs"),
            ("hp", None, "bp", "bs", "cp", "cs"),
            ("hp", "hs", None, "bs", "cp", "cs"),
            ("hp", "hs", "bp", None, "cp", "cs"),
            ("hp", "hs", "bp", "bs", None, "cs"),
            ("hp", "hs", "bp", "bs", "cp", None),
        ]:
            with self.subTest(
                _head_prefix=_head_prefix,
                _head_suffix=_head_suffix,
                _body_prefix=_body_prefix,
                _body_suffix=_body_suffix,
                _code_prefix=_code_prefix,
                _code_suffix=_code_suffix,
            ):
                try:
                    MockExporter._head_prefix = _head_prefix
                    MockExporter._head_suffix = _head_suffix
                    MockExporter._body_prefix = _body_prefix
                    MockExporter._body_suffix = _body_suffix
                    MockExporter._code_prefix = _code_prefix
                    MockExporter._code_suffix = _code_suffix
                    with self.assertRaises(NotImplementedError):
                        MockExporter.export([])
                finally:
                    MockExporter._head_prefix = None
                    MockExporter._head_suffix = None
                    MockExporter._body_prefix = None
                    MockExporter._body_suffix = None
                    MockExporter._code_prefix = None
                    MockExporter._code_suffix = None

    def test_invalid_type(self):
        try:
            MockExporter._head_prefix = "hp"
            MockExporter._head_suffix = "hs\n"
            MockExporter._body_prefix = "bp"
            MockExporter._body_suffix = "bs\n"
            MockExporter._code_prefix = "cp"
            MockExporter._code_suffix = "cs\n"

            with self.assertRaises(TypeError):
                MockExporter.export([None])
        finally:
            MockExporter._head_prefix = None
            MockExporter._head_suffix = None
            MockExporter._body_prefix = None
            MockExporter._body_suffix = None
            MockExporter._code_prefix = None
            MockExporter._code_suffix = None

    def test_main(self):
        try:
            MockExporter._head_prefix = "hp "
            MockExporter._head_suffix = " hs\n"
            MockExporter._body_prefix = "bp "
            MockExporter._body_suffix = " bs\n"
            MockExporter._code_prefix = "cp "
            MockExporter._code_suffix = " cs\n"

            for input_flatdoc, expected_s in [
                ([], ""),
                ([sw_luadocs.flatdoc.FlatElem(txt="he", kind="head")], "hp he hs\n"),
                ([sw_luadocs.flatdoc.FlatElem(txt="be", kind="body")], "bp be bs\n"),
                ([sw_luadocs.flatdoc.FlatElem(txt="ce", kind="code")], "cp ce cs\n"),
                (
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="he", kind="head"),
                        sw_luadocs.flatdoc.FlatElem(txt="be", kind="body"),
                        sw_luadocs.flatdoc.FlatElem(txt="ce", kind="code"),
                    ],
                    "hp he hs\n\nbp be bs\n\ncp ce cs\n",
                ),
                (
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="be", kind="body"),
                        sw_luadocs.flatdoc.FlatElem(txt="ce", kind="code"),
                        sw_luadocs.flatdoc.FlatElem(txt="he", kind="head"),
                    ],
                    "bp be bs\n\ncp ce cs\n\nhp he hs\n",
                ),
                (
                    [
                        sw_luadocs.flatdoc.FlatElem(txt="ce", kind="code"),
                        sw_luadocs.flatdoc.FlatElem(txt="he", kind="head"),
                        sw_luadocs.flatdoc.FlatElem(txt="be", kind="body"),
                    ],
                    "cp ce cs\n\nhp he hs\n\nbp be bs\n",
                ),
            ]:
                with self.subTest(flatdoc=input_flatdoc):
                    actual_s = MockExporter.export(input_flatdoc)
                    self.assertEqual(actual_s, expected_s)
        finally:
            MockExporter._head_prefix = None
            MockExporter._head_suffix = None
            MockExporter._body_prefix = None
            MockExporter._body_suffix = None
            MockExporter._code_prefix = None
            MockExporter._code_suffix = None


class TestExport(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.flatdoc.export([], "invalid")

    def test_main(self):
        for input_flatdoc, input_markup, expected_s in [
            ([sw_luadocs.flatdoc.FlatElem(txt="h", kind="head")], "markdown", "# h\n"),
        ]:
            with self.subTest(flatdoc=input_flatdoc, markup=input_markup):
                actual_s = sw_luadocs.flatdoc.export(input_flatdoc, input_markup)
                self.assertEqual(actual_s, expected_s)


class MockExporter(sw_luadocs.flatdoc.Exporter):
    _head_prefix = None
    _head_suffix = None
    _body_prefix = None
    _body_suffix = None
    _code_prefix = None
    _code_suffix = None
