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
            with self.assertRaises(ValueError):
                sw_luadocs.flatdoc.loads_elem(s)

    def test_kind(self):
        for s, kind in [
            ("[head]", "head"),
            ("[body]", "body"),
            ("[code]", "code"),
            ("[head]\n[body]", "head"),
        ]:
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
            flatelem = sw_luadocs.flatdoc.loads_elem(s)
            self.assertEqual(flatelem.txt, txt)
