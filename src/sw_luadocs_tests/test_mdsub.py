import sw_luadocs.mdsub
import unittest


class TestAsKind(unittest.TestCase):
    def test_validate_value_error(self):
        for v in "head", "body", "code":
            with self.subTest(v=v):
                kind = sw_luadocs.mdsub.as_kind(v)
                self.assertEqual(kind, v)

    def test_validate_value_pass(self):
        with self.assertRaises(ValueError):
            sw_luadocs.mdsub.as_kind("invliad")


class TestDocumentElemPostInit(unittest.TestCase):
    def test_validate_convert(self):
        ocrpara = sw_luadocs.mdsub.DocumentElem(txt=0, kind="head")
        self.assertEqual(ocrpara.txt, "0")
        self.assertEqual(ocrpara.kind, "head")

    def test_validate_convert_kind(self):
        with self.assertRaises(ValueError):
            sw_luadocs.mdsub.DocumentElem(txt="", kind="invalid")
