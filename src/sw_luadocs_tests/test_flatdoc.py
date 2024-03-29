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
        for flatdoc in [
            [sw_luadocs.flatdoc.FlatElem(txt="", kind="head")],
            [sw_luadocs.flatdoc.FlatElem(txt="", kind="body")],
            [sw_luadocs.flatdoc.FlatElem(txt="", kind="code")],
        ]:
            with self.subTest(flatdoc=flatdoc):
                with self.assertRaises(NotImplementedError):
                    sw_luadocs.flatdoc.Exporter.export(flatdoc)

    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.flatdoc.Exporter.export([None])

    def test_main(self):
        for (
            input_flatdoc,
            expected_s,
            expected_export_head_txt,
            expected_export_body_txt,
            expected_export_code_txt,
        ) in [
            ([], "", None, None, None),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="ha", kind="head")],
                "hr",
                "ha",
                None,
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="ba", kind="body")],
                "br",
                None,
                "ba",
                None,
            ),
            (
                [sw_luadocs.flatdoc.FlatElem(txt="ca", kind="code")],
                "cr",
                None,
                None,
                "ca",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ha", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ba", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="ca", kind="code"),
                ],
                "hr\nbr\ncr",
                "ha",
                "ba",
                "ca",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ba", kind="body"),
                    sw_luadocs.flatdoc.FlatElem(txt="ca", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="ha", kind="head"),
                ],
                "br\ncr\nhr",
                "ha",
                "ba",
                "ca",
            ),
            (
                [
                    sw_luadocs.flatdoc.FlatElem(txt="ca", kind="code"),
                    sw_luadocs.flatdoc.FlatElem(txt="ha", kind="head"),
                    sw_luadocs.flatdoc.FlatElem(txt="ba", kind="body"),
                ],
                "cr\nhr\nbr",
                "ha",
                "ba",
                "ca",
            ),
        ]:
            with self.subTest(flatdoc=input_flatdoc):
                try:
                    MockExporter._export_head_txt = None
                    MockExporter._export_body_txt = None
                    MockExporter._export_code_txt = None

                    actual_s = MockExporter.export(input_flatdoc)
                    self.assertEqual(actual_s, expected_s)
                    self.assertEqual(
                        MockExporter._export_head_txt,
                        expected_export_head_txt,
                    )
                    self.assertEqual(
                        MockExporter._export_body_txt,
                        expected_export_body_txt,
                    )
                    self.assertEqual(
                        MockExporter._export_code_txt,
                        expected_export_code_txt,
                    )
                finally:
                    MockExporter._export_head_txt = None
                    MockExporter._export_body_txt = None
                    MockExporter._export_code_txt = None


class TestMarkdownExporterExportHead(unittest.TestCase):
    def test_main(self):
        input_txt = "e"
        expected_s = "# e\n"
        actual_s = sw_luadocs.flatdoc.MarkdownExporter.export_head(input_txt)
        self.assertEqual(expected_s, actual_s)


class TestMarkdownExporterExportBody(unittest.TestCase):
    def test_main(self):
        input_txt = "e"
        expected_s = "e\n"
        actual_s = sw_luadocs.flatdoc.MarkdownExporter.export_body(input_txt)
        self.assertEqual(expected_s, actual_s)


class TestMarkdownExporterExportCode(unittest.TestCase):
    def test_main(self):
        input_txt = "e"
        expected_s = "```lua\ne\n```\n"
        actual_s = sw_luadocs.flatdoc.MarkdownExporter.export_code(input_txt)
        self.assertEqual(expected_s, actual_s)


class TestMarkdownExporterExport(unittest.TestCase):
    def test_main(self):
        input_flatdoc = [
            sw_luadocs.flatdoc.FlatElem(txt="this is head", kind="head"),
            sw_luadocs.flatdoc.FlatElem(txt="this is body", kind="body"),
            sw_luadocs.flatdoc.FlatElem(txt="this is code", kind="code"),
        ]
        expected_s = """\
# this is head

this is body

```lua
this is code
```
"""
        actual_s = sw_luadocs.flatdoc.MarkdownExporter.export(input_flatdoc)
        self.assertEqual(expected_s, actual_s)


class TestWikiWikiExporterExportHead(unittest.TestCase):
    def test_main(self):
        input_txt = "e"
        expected_s = "* e\n"
        actual_s = sw_luadocs.flatdoc.WikiWikiExporter.export_head(input_txt)
        self.assertEqual(expected_s, actual_s)


class TestWikiWikiExporterExportBody(unittest.TestCase):
    def test_main(self):
        input_txt = "e"
        expected_s = "e\n"
        actual_s = sw_luadocs.flatdoc.WikiWikiExporter.export_body(input_txt)
        self.assertEqual(expected_s, actual_s)


class TestWikiWikiExporterExportCode(unittest.TestCase):
    def test_main(self):
        input_txt = "e"
        expected_s = "#code(lua){{\ne\n}}\n"
        actual_s = sw_luadocs.flatdoc.WikiWikiExporter.export_code(input_txt)
        self.assertEqual(expected_s, actual_s)


class TestWikiWikiExporterExport(unittest.TestCase):
    def test_main(self):
        input_flatdoc = [
            sw_luadocs.flatdoc.FlatElem(txt="this is head", kind="head"),
            sw_luadocs.flatdoc.FlatElem(txt="this is body", kind="body"),
            sw_luadocs.flatdoc.FlatElem(txt="this is code", kind="code"),
        ]
        expected_s = """\
* this is head

this is body

#code(lua){{
this is code
}}
"""
        actual_s = sw_luadocs.flatdoc.WikiWikiExporter.export(input_flatdoc)
        self.assertEqual(expected_s, actual_s)


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
    _export_head_txt = None
    _export_body_txt = None
    _export_code_txt = None

    @classmethod
    def export_head(cls, txt):
        cls._export_head_txt = txt
        return "hr"

    @classmethod
    def export_body(cls, txt):
        cls._export_body_txt = txt
        return "br"

    @classmethod
    def export_code(cls, txt):
        cls._export_code_txt = txt
        return "cr"
