import copy
import numpy as np
import sw_luadocs_ocr.ocr
import unittest


class TestOCRLine(unittest.TestCase):
    def test_init(self):
        # type conversion
        ocrline = sw_luadocs_ocr.ocr.OCRLine(
            txt=0, kind="head", box=["1", "2", "3", "4"]
        )
        self.assertEqual(ocrline.txt, "0")
        self.assertEqual(ocrline.kind, "head")
        self.assertEqual(ocrline.box, (1, 2, 3, 4))

        # kind check: head
        ocrline = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(1, 2, 3, 4))
        self.assertEqual(ocrline.kind, "head")

        # kind check: body
        ocrline = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="body", box=(1, 2, 3, 4))
        self.assertEqual(ocrline.kind, "body")

        # kind check: code
        ocrline = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="code", box=(1, 2, 3, 4))
        self.assertEqual(ocrline.kind, "code")

        # kind check: invalid
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRLine(txt="", kind="invalid", box=(1, 2, 3, 4))

        # box length: ok
        ocrline = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(1, 2, 3, 4))
        self.assertEqual(ocrline.box, (1, 2, 3, 4))

        # box length: small
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(1, 2, 3))

        # box length: big
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(1, 2, 3, 4, 5))

        # box: ok
        ocrline = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, 0, 0))
        self.assertEqual(ocrline.box, (0, 0, 0, 0))

        # box: x < 0
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(-1, 0, 0, 0))

        # box: y < 0
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, -1, 0, 0))

        # box: w < 0
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, -1, 0))

        # box: h < 0
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, 0, -1))

    def test_eq(self):
        # type mismatch
        lop = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, 0, 0))
        rop = None
        self.assertNotEqual(lop, rop)

        # txt mismatch
        lop = sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="head", box=(0, 0, 0, 0))
        rop = sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="head", box=(0, 0, 0, 0))
        self.assertNotEqual(lop, rop)

        # kind mismatch
        lop = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, 0, 0))
        rop = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="body", box=(0, 0, 0, 0))
        self.assertNotEqual(lop, rop)

        # box mismatch
        lop = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, 0, 0))
        rop = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, 0, 1))
        self.assertNotEqual(lop, rop)

        # match
        lop = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, 0, 0))
        rop = sw_luadocs_ocr.ocr.OCRLine(txt="", kind="head", box=(0, 0, 0, 0))
        self.assertEqual(lop, rop)


class TestOCRParagraph(unittest.TestCase):
    def test_init(self):
        # type conversion
        ocrpara = sw_luadocs_ocr.ocr.OCRParagraph(txt=0, kind="head")
        self.assertEqual(ocrpara.txt, "0")
        self.assertEqual(ocrpara.kind, "head")

        # kind check: head
        ocrpara = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="head")
        self.assertEqual(ocrpara.kind, "head")

        # kind check: body
        ocrpara = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="body")
        self.assertEqual(ocrpara.kind, "body")

        # kind check: code
        ocrpara = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="code")
        self.assertEqual(ocrpara.kind, "code")

        # kind check: invalid
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="invalid")

    def test_eq(self):
        # type mismatch
        lop = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="head")
        rop = None
        self.assertNotEqual(lop, rop)

        # txt mismatch
        lop = sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="head")
        rop = sw_luadocs_ocr.ocr.OCRParagraph(txt="b", kind="head")
        self.assertNotEqual(lop, rop)

        # kind mismatch
        lop = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="head")
        rop = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="body")
        self.assertNotEqual(lop, rop)

        # match
        lop = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="head")
        rop = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="head")
        self.assertEqual(lop, rop)


class TestOCR(unittest.TestCase):
    def test_as_tesstsv(self):
        # type conversion
        v = {
            "level": ["0", "1"],
            "page_num": ["10", "11"],
            "block_num": ["20", "21"],
            "par_num": ["30", "31"],
            "line_num": ["40", "41"],
            "word_num": ["50", "51"],
            "left": ["60", "61"],
            "top": ["70", "71"],
            "width": ["80", "81"],
            "height": ["90", "91"],
            "conf": ["0.5", "1.5"],
            "text": [100, 101],
        }
        tesstsv = sw_luadocs_ocr.ocr.as_tesstsv(v)
        self.assertEqual(
            tesstsv,
            {
                "level": [0, 1],
                "page_num": [10, 11],
                "block_num": [20, 21],
                "par_num": [30, 31],
                "line_num": [40, 41],
                "word_num": [50, 51],
                "left": [60, 61],
                "top": [70, 71],
                "width": [80, 81],
                "height": [90, 91],
                "conf": [0.5, 1.5],
                "text": ["100", "101"],
            },
        )

        # copy
        v = {
            "level": [0, 1],
            "page_num": [10, 11],
            "block_num": [20, 21],
            "par_num": [30, 31],
            "line_num": [40, 41],
            "word_num": [50, 51],
            "left": [60, 61],
            "top": [70, 71],
            "width": [80, 81],
            "height": [90, 91],
            "conf": [0.5, 1.5],
            "text": ["100", "101"],
        }
        tesstsv = sw_luadocs_ocr.ocr.as_tesstsv(v)
        self.assertIsNot(tesstsv, v)
        self.assertEqual(tesstsv, v)

        # wrong length of v[key]
        v = {
            "level": [0],
            "page_num": [0],
            "block_num": [0],
            "par_num": [0],
            "line_num": [0],
            "word_num": [0],
            "left": [0],
            "top": [0],
            "width": [0],
            "height": [0],
            "conf": [0],
            "text": [0],
        }
        for key in v:
            v2 = copy.deepcopy(v)
            v2[key] = [0, 1]
            with self.assertRaises(ValueError):
                sw_luadocs_ocr.ocr.as_tesstsv(v2)

    def as_tessline(self):
        # type convertsion
        v = {"txt": 0, "box": ["1", "2", "3", "4"]}
        tessline = sw_luadocs_ocr.ocr.as_tessline(v)
        self.assertEqual(tessline, {"txt": "0", "box": (1, 2, 3, 4)})

        # copy
        v = {"txt": "0", "box": (1, 2, 3, 4)}
        tessline = sw_luadocs_ocr.ocr.as_tessline(v)
        self.assertIsNot(tessline, v)
        self.assertEqual(tessline, v)

        # box length
        v = {"txt": "0", "box": (1, 2, 3, 4, 5)}
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.as_tessline(v)

    def test_combine_tesstsv_into_tessline(self):
        # empty tesstsv
        tesstsv = {
            "level": [],
            "page_num": [],
            "block_num": [],
            "par_num": [],
            "line_num": [],
            "word_num": [],
            "left": [],
            "top": [],
            "width": [],
            "height": [],
            "conf": [],
            "text": [],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(tessline_list, [])

        # no line
        tesstsv = {
            "level": [1, 2, 3, 5],
            "page_num": [1, 1, 1, 1],
            "block_num": [1, 1, 1, 1],
            "par_num": [1, 1, 1, 1],
            "line_num": [1, 1, 1, 1],
            "word_num": [1, 1, 1, 1],
            "left": [0, 0, 0, 0],
            "top": [0, 0, 0, 0],
            "width": [0, 0, 0, 0],
            "height": [0, 0, 0, 0],
            "conf": [0, 0, 0, 0],
            "text": ["", "", "", ""],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(tessline_list, [])

        # line only
        tesstsv = {
            "level": [4],
            "page_num": [1],
            "block_num": [1],
            "par_num": [1],
            "line_num": [1],
            "word_num": [1],
            "left": [0],
            "top": [1],
            "width": [2],
            "height": [3],
            "conf": [0],
            "text": ["text"],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(tessline_list, [{"txt": "", "box": (0, 1, 2, 3)}])

        # line and other
        tesstsv = {
            "level": [1, 2, 3, 4, 3, 4],
            "page_num": [1, 1, 1, 1, 1, 1],
            "block_num": [1, 1, 1, 1, 1, 1],
            "par_num": [1, 1, 1, 1, 1, 1],
            "line_num": [1, 1, 1, 1, 1, 1],
            "word_num": [1, 1, 1, 1, 1, 1],
            "left": [1, 2, 3, 4, 5, 6],
            "top": [1, 2, 3, 4, 5, 6],
            "width": [1, 2, 3, 4, 5, 6],
            "height": [1, 2, 3, 4, 5, 6],
            "conf": [0, 0, 0, 0, 0, 0],
            "text": ["1", "2", "3", "4", "5", "6"],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(
            tessline_list,
            [
                {"txt": "", "box": (4, 4, 4, 4)},
                {"txt": "", "box": (6, 6, 6, 6)},
            ],
        )

        # single text only
        tesstsv = {
            "level": [4, 5],
            "page_num": [1, 1],
            "block_num": [1, 1],
            "par_num": [1, 1],
            "line_num": [1, 1],
            "word_num": [1, 1],
            "left": [4, 5],
            "top": [4, 5],
            "width": [4, 5],
            "height": [4, 5],
            "conf": [0, 0],
            "text": ["4", "5"],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(tessline_list, [{"txt": "5", "box": (4, 4, 4, 4)}])

        # multiple text only
        tesstsv = {
            "level": [4, 5, 5],
            "page_num": [1, 1, 1],
            "block_num": [1, 1, 1],
            "par_num": [1, 1, 1],
            "line_num": [1, 1, 1],
            "word_num": [1, 1, 1],
            "left": [4, 5, 6],
            "top": [4, 5, 6],
            "width": [4, 5, 6],
            "height": [4, 5, 6],
            "conf": [0, 0, 0],
            "text": ["4", "5", "6"],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(tessline_list, [{"txt": "5 6", "box": (4, 4, 4, 4)}])

        # multiple text and other
        tesstsv = {
            "level": [4, 5, 6, 5],
            "page_num": [1, 1, 1, 1],
            "block_num": [1, 1, 1, 1],
            "par_num": [1, 1, 1, 1],
            "line_num": [1, 1, 1, 1],
            "word_num": [1, 1, 1, 1],
            "left": [1, 2, 3, 4],
            "top": [1, 2, 3, 4],
            "width": [1, 2, 3, 4],
            "height": [1, 2, 3, 4],
            "conf": [0, 0, 0, 0],
            "text": ["1", "2", "3", "4"],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(tessline_list, [{"txt": "2 4", "box": (1, 1, 1, 1)}])

        # line and text
        tesstsv = {
            "level": [4, 5, 3, 4, 5],
            "page_num": [1, 1, 1, 1, 1],
            "block_num": [1, 1, 1, 1, 1],
            "par_num": [1, 1, 1, 1, 1],
            "line_num": [1, 1, 1, 1, 1],
            "word_num": [1, 1, 1, 1, 1],
            "left": [1, 2, 3, 4, 5],
            "top": [1, 2, 3, 4, 5],
            "width": [1, 2, 3, 4, 5],
            "height": [1, 2, 3, 4, 5],
            "conf": [0, 0, 0, 0, 0],
            "text": ["1", "2", "3", "4", "5"],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(
            tessline_list,
            [
                {"txt": "2", "box": (1, 1, 1, 1)},
                {"txt": "5", "box": (4, 4, 4, 4)},
            ],
        )

        tesstsv = {
            "level": [
                1,
                2,
                3,
                4,
                5,
                5,
                5,
                5,
                3,
                4,
                5,
                5,
                5,
                5,
                4,
                5,
                5,
                5,
                3,
                4,
                5,
                5,
                5,
            ],
            "page_num": [
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
            ],
            "block_num": [
                0,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
                1,
            ],
            "par_num": [
                0,
                0,
                1,
                1,
                1,
                1,
                1,
                1,
                2,
                2,
                2,
                2,
                2,
                2,
                2,
                2,
                2,
                2,
                3,
                3,
                3,
                3,
                3,
            ],
            "line_num": [
                0,
                0,
                0,
                1,
                1,
                1,
                1,
                1,
                0,
                1,
                1,
                1,
                1,
                1,
                2,
                2,
                2,
                2,
                0,
                1,
                1,
                1,
                1,
            ],
            "word_num": [
                0,
                0,
                0,
                0,
                1,
                2,
                3,
                4,
                0,
                0,
                1,
                2,
                3,
                4,
                0,
                1,
                2,
                3,
                0,
                0,
                1,
                2,
                3,
            ],
            "left": [
                0,
                1,
                2,
                2,
                2,
                77,
                115,
                196,
                1,
                14,
                14,
                118,
                137,
                373,
                1,
                1,
                58,
                74,
                14,
                14,
                14,
                118,
                137,
            ],
            "top": [
                0,
                10,
                10,
                10,
                10,
                13,
                13,
                10,
                34,
                34,
                34,
                39,
                34,
                34,
                70,
                70,
                73,
                72,
                93,
                93,
                94,
                98,
                93,
            ],
            "width": [
                475,
                445,
                273,
                273,
                69,
                31,
                74,
                79,
                445,
                432,
                93,
                8,
                223,
                73,
                133,
                50,
                8,
                60,
                328,
                328,
                93,
                8,
                205,
            ],
            "height": [
                122,
                99,
                19,
                19,
                18,
                11,
                11,
                19,
                50,
                16,
                16,
                5,
                16,
                15,
                14,
                14,
                11,
                12,
                16,
                16,
                15,
                6,
                16,
            ],
            "conf": [
                "-1",
                "-1",
                "-1",
                "-1",
                "96.368584",
                "96.435768",
                "96.435768",
                "96.058655",
                "-1",
                "-1",
                "91.057083",
                "93.249252",
                "76.489006",
                "90.753517",
                "-1",
                "96.569305",
                "96.826935",
                "96.665543",
                "-1",
                "-1",
                "90.783691",
                "93.222092",
                "75.015419",
            ],
            "text": [
                "",
                "",
                "",
                "",
                "Multiply",
                "two",
                "matrices",
                "together.",
                "",
                "",
                "out_matrix",
                "=",
                "matrix.multiply(matrixl,",
                "matrix2)",
                "",
                "Invert",
                "a",
                "matrix.",
                "",
                "",
                "out_matrix",
                "=",
                "matrix.invert(matrix1)",
            ],
        }
        tessline_list = sw_luadocs_ocr.ocr.combine_tesstsv_into_tessline(tesstsv)
        tessline_list = list(tessline_list)
        self.assertEqual(
            tessline_list,
            [
                {
                    "txt": "Multiply two matrices together.",
                    "box": (2, 10, 273, 19),
                },
                {
                    "txt": "out_matrix = matrix.multiply(matrixl, matrix2)",
                    "box": (14, 34, 432, 16),
                },
                {"txt": "Invert a matrix.", "box": (1, 70, 133, 14)},
                {
                    "txt": "out_matrix = matrix.invert(matrix1)",
                    "box": (14, 93, 328, 16),
                },
            ],
        )

    def test_categorize_tessline(self):
        # code
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (1, 0, 0, 0)},
            capture_img=np.zeros((1, 1, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=0,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "code")

        # body: empty box
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 0, 0)},
            capture_img=np.zeros((1, 1, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=0,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "body")

        # body: bg only
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 1, 1)},
            capture_img=np.zeros((10, 10, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=0,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "body")

        # body: low saturation
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 1, 1)},
            capture_img=np.ones((10, 10, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "body")

        # head
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 1, 1)},
            capture_img=np.ones((10, 10, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=0,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

        # crop
        capture_img = np.ones((10, 10, 3), dtype=np.uint8)
        capture_img[2:6, 1:4, :] = 0
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (1, 2, 3, 4)},
            capture_img=capture_img,
            code_thresh_x=10,
            head_thresh_s=0,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "body")

        # bg_thresh: body
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 1, 1)},
            capture_img=np.ones((10, 10, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=0,
            bg_thresh_rgb=(1, 1, 1),
        )
        self.assertEqual(kind, "body")

        # bg_thresh: r
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 1, 1)},
            capture_img=np.ones((10, 10, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=0,
            bg_thresh_rgb=(0, 1, 1),
        )
        self.assertEqual(kind, "head")

        # bg_thresh: g
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 1, 1)},
            capture_img=np.ones((10, 10, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=0,
            bg_thresh_rgb=(1, 0, 1),
        )
        self.assertEqual(kind, "head")

        # bg_thresh: b
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 1, 1)},
            capture_img=np.ones((10, 10, 3), dtype=np.uint8),
            code_thresh_x=1,
            head_thresh_s=0,
            bg_thresh_rgb=(1, 1, 0),
        )
        self.assertEqual(kind, "head")

        # saturation: zero
        capture_img = np.ones((10, 10, 3), dtype=np.uint8)
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 10, 10)},
            capture_img=capture_img,
            code_thresh_x=1,
            head_thresh_s=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "body")

        # saturation: r max
        capture_img = np.ones((10, 10, 3), dtype=np.uint8)
        capture_img[:, :, 0] = 255
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 10, 10)},
            capture_img=capture_img,
            code_thresh_x=1,
            head_thresh_s=255,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

        # saturation: g max
        capture_img = np.ones((10, 10, 3), dtype=np.uint8)
        capture_img[:, :, 1] = 255
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 10, 10)},
            capture_img=capture_img,
            code_thresh_x=1,
            head_thresh_s=255,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

        # saturation: b max
        capture_img = np.ones((10, 10, 3), dtype=np.uint8)
        capture_img[:, :, 2] = 255
        kind = sw_luadocs_ocr.ocr.categorize_tessline(
            tessline={"txt": "", "box": (0, 0, 10, 10)},
            capture_img=capture_img,
            code_thresh_x=1,
            head_thresh_s=255,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

    def test_calc_code_indent(self):
        # space_w <= 0
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.calc_code_indent(line_x=0, base_x=0, space_w=0)

        # line_x < base_x
        indent = sw_luadocs_ocr.ocr.calc_code_indent(line_x=0, base_x=1, space_w=0.1)
        self.assertEqual(indent, 0)

        # zero
        indent = sw_luadocs_ocr.ocr.calc_code_indent(line_x=1, base_x=1, space_w=0.1)
        self.assertEqual(indent, 0)

        # normal
        indent = sw_luadocs_ocr.ocr.calc_code_indent(line_x=2, base_x=1, space_w=0.1)
        self.assertEqual(indent, 10)

        # round
        indent = sw_luadocs_ocr.ocr.calc_code_indent(line_x=2, base_x=1, space_w=0.4)
        self.assertEqual(indent, 2)

    def test_create_ocrline(self):
        # code_thresh_x: code
        ocrline = sw_luadocs_ocr.ocr.create_ocrline(
            tessline={"txt": "", "box": (9, 0, 1, 1)},
            capture_img=np.zeros((10, 10, 3), dtype=np.uint8),
            bg_thresh_rgb=(40, 40, 40),
            head_thresh_s=9,
            code_base_x=14,
            code_space_w=9.5,
        )
        self.assertEqual(ocrline.kind, "code")

        # code_thresh_x: body
        ocrline = sw_luadocs_ocr.ocr.create_ocrline(
            tessline={"txt": "", "box": (8, 0, 1, 1)},
            capture_img=np.zeros((10, 10, 3), dtype=np.uint8),
            bg_thresh_rgb=(40, 40, 40),
            head_thresh_s=9,
            code_base_x=14,
            code_space_w=9.5,
        )
        self.assertEqual(ocrline.kind, "body")

        # indent
        ocrline = sw_luadocs_ocr.ocr.create_ocrline(
            tessline={"txt": "a", "box": (52, 0, 1, 1)},
            capture_img=np.zeros((100, 100, 3), dtype=np.uint8),
            bg_thresh_rgb=(40, 40, 40),
            head_thresh_s=9,
            code_base_x=14,
            code_space_w=9.5,
        )
        self.assertEqual(ocrline.txt, "    a")

        # init
        ocrline = sw_luadocs_ocr.ocr.create_ocrline(
            tessline={"txt": "a", "box": (1, 2, 3, 4)},
            capture_img=np.zeros((10, 10, 3), dtype=np.uint8),
            bg_thresh_rgb=(40, 40, 40),
            head_thresh_s=9,
            code_base_x=14,
            code_space_w=9.5,
        )
        self.assertIsInstance(ocrline, sw_luadocs_ocr.ocr.OCRLine)
        self.assertEqual(ocrline.txt, "a")
        self.assertEqual(ocrline.kind, "body")
        self.assertEqual(ocrline.box, (1, 2, 3, 4))

    def test_create_ocrpara_list(self):
        # empty
        ocrline_list = []
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(ocrline_list)
        self.assertEqual(ocrpara_list, [])

        # single head
        ocrline_list = [
            sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="head", box=(0, 0, 0, 0)),
        ]
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(ocrline_list)
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="head")]
        )

        # single body
        ocrline_list = [
            sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="body", box=(0, 0, 0, 0)),
        ]
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(ocrline_list)
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="body")]
        )

        # single code
        ocrline_list = [
            sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="code", box=(0, 0, 0, 0)),
        ]
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(ocrline_list)
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="code")]
        )

        # multiple head
        ocrline_list = [
            sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="head", box=(0, 0, 0, 0)),
            sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="head", box=(0, 0, 0, 0)),
        ]
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(ocrline_list)
        self.assertEqual(
            ocrpara_list,
            [
                sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="head"),
                sw_luadocs_ocr.ocr.OCRParagraph(txt="b", kind="head"),
            ],
        )

        # multiple body
        ocrline_list = [
            sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="body", box=(0, 0, 0, 0)),
            sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="body", box=(0, 0, 0, 0)),
        ]
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(ocrline_list)
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a b", kind="body")]
        )

        # multiple code
        ocrline_list = [
            sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="code", box=(0, 0, 0, 0)),
            sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="code", box=(0, 0, 0, 0)),
        ]
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(ocrline_list)
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a\nb", kind="code")]
        )

        # mix kind
        ocrline_list = [
            sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="head", box=(0, 0, 0, 0)),
            sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="body", box=(0, 0, 0, 0)),
            sw_luadocs_ocr.ocr.OCRLine(txt="c", kind="code", box=(0, 0, 0, 0)),
            sw_luadocs_ocr.ocr.OCRLine(txt="d", kind="head", box=(0, 0, 0, 0)),
        ]
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(ocrline_list)
        self.assertEqual(
            ocrpara_list,
            [
                sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="head"),
                sw_luadocs_ocr.ocr.OCRParagraph(txt="b", kind="body"),
                sw_luadocs_ocr.ocr.OCRParagraph(txt="c", kind="code"),
                sw_luadocs_ocr.ocr.OCRParagraph(txt="d", kind="head"),
            ],
        )
