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
        docelem = sw_luadocs.flatdoc.DocumentElem(txt=0, kind="head")
        self.assertEqual(docelem.txt, "0")
        self.assertEqual(docelem.kind, "head")

    def test_validate_convert_kind(self):
        with self.assertRaises(ValueError):
            sw_luadocs.flatdoc.DocumentElem(txt="", kind="invalid")
