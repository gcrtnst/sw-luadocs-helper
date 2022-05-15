import copy
import numpy as np
import sw_luadocs_ocr.ocr
import unittest


class TestAsTessTSV(unittest.TestCase):
    def test_type(self):
        v = {
            "level": ("0", "1"),
            "page_num": ("10", "11"),
            "block_num": ("20", "21"),
            "par_num": ("30", "31"),
            "line_num": ("40", "41"),
            "word_num": ("50", "51"),
            "left": ("60", "61"),
            "top": ("70", "71"),
            "width": ("80", "81"),
            "height": ("90", "91"),
            "conf": ("0.5", "1.5"),
            "text": (100, 101),
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

    def test_copy(self):
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

    def test_len(self):
        v1 = {
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
        for key in v1:
            with self.subTest(key=key):
                v2 = copy.deepcopy(v1)
                v2[key] = [0, 1]
                with self.assertRaises(ValueError):
                    sw_luadocs_ocr.ocr.as_tesstsv(v2)


class TestAsBox(unittest.TestCase):
    def test_type(self):
        box = sw_luadocs_ocr.ocr.as_box(["10", "11", "12", "13"])
        self.assertEqual(box, (10, 11, 12, 13))

    def test_valid(self):
        v = (0, 0, 1, 1)
        box = sw_luadocs_ocr.ocr.as_box(v)
        self.assertEqual(box, v)

    def test_invalid(self):
        for v in (
            (0, 0, 1),
            (0, 0, 1, 1, 1),
            (-1, 0, 1, 1),
            (0, -1, 1, 1),
            (0, 0, 0, 1),
            (0, 0, 1, 0),
        ):
            with self.subTest(v=v):
                with self.assertRaises(ValueError):
                    sw_luadocs_ocr.ocr.as_box(v)


class TestAsKind(unittest.TestCase):
    def test_valid(self):
        for v in "head", "body", "code":
            with self.subTest(v=v):
                kind = sw_luadocs_ocr.ocr.as_kind(v)
                self.assertEqual(kind, v)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.as_kind("invliad")


class TestTesseractLinePostInit(unittest.TestCase):
    def test_type(self):
        tessline = sw_luadocs_ocr.ocr.TesseractLine(txt=0, box=["10", "11", "12", "13"])
        self.assertEqual(tessline.txt, "0")
        self.assertEqual(tessline.box, (10, 11, 12, 13))


class TestTesseractLineIterFromTessTSV(unittest.TestCase):
    def test_type(self):
        it = sw_luadocs_ocr.ocr.TesseractLine.iter_from_tesstsv(
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
                "text": ["100", "101", "102"],
            }
        )
        with self.assertRaises(ValueError):
            next(it)

    def test_combine(self):
        for msg, input_tesstsv, expected_tessline_list in [
            (
                "empty",
                {
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
                },
                [],
            ),
            (
                "no line, no word, other",
                {
                    "level": [1, 2, 3, 5],
                    "page_num": [1, 1, 1, 1],
                    "block_num": [1, 1, 1, 1],
                    "par_num": [1, 1, 1, 1],
                    "line_num": [1, 1, 1, 1],
                    "word_num": [1, 1, 1, 1],
                    "left": [0, 0, 0, 0],
                    "top": [0, 0, 0, 0],
                    "width": [1, 1, 1, 1],
                    "height": [1, 1, 1, 1],
                    "conf": [0, 0, 0, 0],
                    "text": ["", "", "", ""],
                },
                [],
            ),
            (
                "single line, no word",
                {
                    "level": [4],
                    "page_num": [1],
                    "block_num": [1],
                    "par_num": [1],
                    "line_num": [1],
                    "word_num": [1],
                    "left": [10],
                    "top": [11],
                    "width": [12],
                    "height": [13],
                    "conf": [0],
                    "text": ["text"],
                },
                [sw_luadocs_ocr.ocr.TesseractLine(txt="", box=(10, 11, 12, 13))],
            ),
            (
                "multiple line, no word, other",
                {
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
                },
                [
                    sw_luadocs_ocr.ocr.TesseractLine(txt="", box=(4, 4, 4, 4)),
                    sw_luadocs_ocr.ocr.TesseractLine(txt="", box=(6, 6, 6, 6)),
                ],
            ),
            (
                "single line, single word",
                {
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
                },
                [sw_luadocs_ocr.ocr.TesseractLine(txt="5", box=(4, 4, 4, 4))],
            ),
            (
                "single line, multiple word",
                {
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
                },
                [sw_luadocs_ocr.ocr.TesseractLine(txt="5 6", box=(4, 4, 4, 4))],
            ),
            (
                "single line, multiple word, other",
                {
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
                },
                [sw_luadocs_ocr.ocr.TesseractLine(txt="2 4", box=(1, 1, 1, 1))],
            ),
            (
                "multiple line, single word, other",
                {
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
                },
                [
                    sw_luadocs_ocr.ocr.TesseractLine(txt="2", box=(1, 1, 1, 1)),
                    sw_luadocs_ocr.ocr.TesseractLine(txt="5", box=(4, 4, 4, 4)),
                ],
            ),
            (
                "real",
                {
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
                },
                [
                    sw_luadocs_ocr.ocr.TesseractLine(
                        txt="Multiply two matrices together.",
                        box=(2, 10, 273, 19),
                    ),
                    sw_luadocs_ocr.ocr.TesseractLine(
                        txt="out_matrix = matrix.multiply(matrixl, matrix2)",
                        box=(14, 34, 432, 16),
                    ),
                    sw_luadocs_ocr.ocr.TesseractLine(
                        txt="Invert a matrix.",
                        box=(1, 70, 133, 14),
                    ),
                    sw_luadocs_ocr.ocr.TesseractLine(
                        txt="out_matrix = matrix.invert(matrix1)",
                        box=(14, 93, 328, 16),
                    ),
                ],
            ),
        ]:
            with self.subTest(msg):
                output_tessline_list = (
                    sw_luadocs_ocr.ocr.TesseractLine.iter_from_tesstsv(input_tesstsv)
                )
                output_tessline_list = list(output_tessline_list)
                self.assertEqual(output_tessline_list, expected_tessline_list)


class TestOCRLinePostInit(unittest.TestCase):
    def test_type(self):
        ocrline = sw_luadocs_ocr.ocr.OCRLine(
            txt=0, kind="head", box=["1", "2", "3", "4"]
        )
        self.assertEqual(ocrline.txt, "0")
        self.assertEqual(ocrline.kind, "head")
        self.assertEqual(ocrline.box, (1, 2, 3, 4))

    def test_kind_valid(self):
        for kind in "head", "body", "code":
            with self.subTest(kind=kind):
                ocrline = sw_luadocs_ocr.ocr.OCRLine(
                    txt="", kind=kind, box=(1, 2, 3, 4)
                )
                self.assertEqual(ocrline.kind, kind)

    def test_kind_invalid(self):
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRLine(txt="", kind="invalid", box=(1, 2, 3, 4))


class TestOCRParagraphPostInit(unittest.TestCase):
    def test_type(self):
        ocrpara = sw_luadocs_ocr.ocr.OCRParagraph(txt=0, kind="head")
        self.assertEqual(ocrpara.txt, "0")
        self.assertEqual(ocrpara.kind, "head")

    def test_kind_valid(self):
        for kind in "head", "body", "code":
            with self.subTest(kind=kind):
                ocrpara = sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind=kind)
                self.assertEqual(ocrpara.kind, kind)

    def test_kind_invalid(self):
        with self.assertRaises(ValueError):
            sw_luadocs_ocr.ocr.OCRParagraph(txt="", kind="invalid")


class TestPreprocessImage(unittest.TestCase):
    def test_axis(self):
        input_img = np.array([[51, 102], [153, 204]], dtype=np.uint8)
        expected_img = np.array([[204, 153], [102, 51]], dtype=np.uint8)
        output_img = sw_luadocs_ocr.ocr.preprocess_image(input_img)
        self.assertTrue(np.array_equal(output_img, expected_img))

    def test_value(self):
        input_img = np.array(
            [[[0, 0, 0], [0, 0, 1]], [[0, 2, 0], [3, 0, 0]]],
            dtype=np.uint8,
        )
        expected_img = np.array(
            [[255, 254], [253, 252]],
            dtype=np.uint8,
        )
        output_img = sw_luadocs_ocr.ocr.preprocess_image(input_img)
        self.assertTrue(np.array_equal(output_img, expected_img))


class TestOCR(unittest.TestCase):
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
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[], code_line_h=16.5
        )
        self.assertEqual(ocrpara_list, [])

        # single head
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="head")]
        )

        # single body
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="body", box=(0, 0, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="body")]
        )

        # single code
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="code", box=(0, 0, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="code")]
        )

        # multiple head
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1)),
                sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="head", box=(0, 0, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list,
            [
                sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="head"),
                sw_luadocs_ocr.ocr.OCRParagraph(txt="b", kind="head"),
            ],
        )

        # multiple body
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="body", box=(0, 0, 1, 1)),
                sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="body", box=(0, 0, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a b", kind="body")]
        )

        # multiple code
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="code", box=(0, 0, 1, 1)),
                sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="code", box=(0, 0, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a\nb", kind="code")]
        )

        # code linefeed: normal
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="code", box=(0, 0, 1, 1)),
                sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="code", box=(0, 33, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a\n\nb", kind="code")]
        )

        # code linefeed: round
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="code", box=(0, 0, 1, 1)),
                sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="code", box=(0, 45, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list, [sw_luadocs_ocr.ocr.OCRParagraph(txt="a\n\n\nb", kind="code")]
        )

        # mix kind
        ocrpara_list = sw_luadocs_ocr.ocr.create_ocrpara_list(
            ocrline_list=[
                sw_luadocs_ocr.ocr.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1)),
                sw_luadocs_ocr.ocr.OCRLine(txt="b", kind="body", box=(0, 0, 1, 1)),
                sw_luadocs_ocr.ocr.OCRLine(txt="c", kind="code", box=(0, 0, 1, 1)),
                sw_luadocs_ocr.ocr.OCRLine(txt="d", kind="head", box=(0, 0, 1, 1)),
            ],
            code_line_h=16.5,
        )
        self.assertEqual(
            ocrpara_list,
            [
                sw_luadocs_ocr.ocr.OCRParagraph(txt="a", kind="head"),
                sw_luadocs_ocr.ocr.OCRParagraph(txt="b", kind="body"),
                sw_luadocs_ocr.ocr.OCRParagraph(txt="c", kind="code"),
                sw_luadocs_ocr.ocr.OCRParagraph(txt="d", kind="head"),
            ],
        )
