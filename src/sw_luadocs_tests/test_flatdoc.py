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
