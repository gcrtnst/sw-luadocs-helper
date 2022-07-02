import copy
import numpy as np
import sw_luadocs.flatdoc
import sw_luadocs.recognize
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
        tesstsv = sw_luadocs.recognize.as_tesstsv(v)
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
        tesstsv = sw_luadocs.recognize.as_tesstsv(v)
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
                    sw_luadocs.recognize.as_tesstsv(v2)


class TestAsBox(unittest.TestCase):
    def test_type(self):
        box = sw_luadocs.recognize.as_box(["10", "11", "12", "13"])
        self.assertEqual(box, (10, 11, 12, 13))

    def test_valid(self):
        v = (0, 0, 1, 1)
        box = sw_luadocs.recognize.as_box(v)
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
                    sw_luadocs.recognize.as_box(v)


class TestTesseractLinePostInit(unittest.TestCase):
    def test_type(self):
        tessline = sw_luadocs.recognize.TesseractLine(
            txt=0, box=["10", "11", "12", "13"]
        )
        self.assertEqual(tessline.txt, "0")
        self.assertEqual(tessline.box, (10, 11, 12, 13))


class TestOCRLinePostInit(unittest.TestCase):
    def test_type(self):
        ocrline = sw_luadocs.recognize.OCRLine(
            txt=0, kind="head", box=["1", "2", "3", "4"]
        )
        self.assertEqual(ocrline.txt, "0")
        self.assertEqual(ocrline.kind, "head")
        self.assertEqual(ocrline.box, (1, 2, 3, 4))

    def test_kind_invalid(self):
        with self.assertRaises(ValueError):
            sw_luadocs.recognize.OCRLine(txt="", kind="invalid", box=(1, 2, 3, 4))


class TestAsOCRLineList(unittest.TestCase):
    def test_type(self):
        v = [
            sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1)),
            sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1)),
            sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1)),
        ]

        def gen():
            yield from v

        ocrline_list = sw_luadocs.recognize.as_ocrline_list(gen())
        self.assertIsInstance(ocrline_list, list)
        self.assertEqual(ocrline_list, v)

    def test_validate_pass(self):
        v = [
            sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1)),
            sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1)),
            sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1)),
        ]
        ocrline_list = sw_luadocs.recognize.as_ocrline_list(v)
        self.assertIsInstance(ocrline_list, list)
        self.assertEqual(ocrline_list, v)

    def test_validate_error(self):
        for v in [
            [
                None,
                sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1)),
            ],
            [
                sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1)),
                None,
                sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1)),
            ],
            [
                sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1)),
                None,
            ],
        ]:
            with self.subTest(v=v):
                with self.assertRaises(TypeError):
                    sw_luadocs.recognize.as_ocrline_list(v)


class TestAsOCRLineListMonoKind(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.recognize.as_ocrline_list_monokind([None])

    def test_validate_value_error(self):
        for v, kind in [
            ([], "invalid"),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="head", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="head", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="body", box=(0, 0, 1, 1)
                    ),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="body", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="body", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="code", box=(0, 0, 1, 1)
                    ),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="code", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="code", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="head", box=(0, 0, 1, 1)
                    ),
                ],
                None,
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1))],
                "body",
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="body", box=(0, 0, 1, 1))],
                "code",
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="code", box=(0, 0, 1, 1))],
                "head",
            ),
        ]:
            with self.subTest(v=v, kind=kind):
                with self.assertRaises(ValueError):
                    sw_luadocs.recognize.as_ocrline_list_monokind(v, kind=kind)

    def test_main(self):
        for v, kind in [
            ([], None),
            ([], "head"),
            ([], "body"),
            ([], "code"),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1))],
                None,
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="body", box=(0, 0, 1, 1))],
                None,
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="code", box=(0, 0, 1, 1))],
                None,
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1))],
                "head",
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="body", box=(0, 0, 1, 1))],
                "body",
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="code", box=(0, 0, 1, 1))],
                "code",
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="head", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="head", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="head", box=(0, 0, 1, 1)
                    ),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="body", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="body", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="body", box=(0, 0, 1, 1)
                    ),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="code", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="code", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="code", box=(0, 0, 1, 1)
                    ),
                ],
                None,
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="head", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="head", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="head", box=(0, 0, 1, 1)
                    ),
                ],
                "head",
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="body", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="body", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="body", box=(0, 0, 1, 1)
                    ),
                ],
                "body",
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="code", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="code", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="code", box=(0, 0, 1, 1)
                    ),
                ],
                "code",
            ),
        ]:
            with self.subTest(v=v, kind=kind):
                ocrline_list = sw_luadocs.recognize.as_ocrline_list_monokind(
                    v, kind=kind
                )
                self.assertIs(type(ocrline_list), list)
                self.assertEqual(ocrline_list, v)


class TestPreprocessImage(unittest.TestCase):
    def test_axis(self):
        input_img = np.array([[51, 102], [153, 204]], dtype=np.uint8)
        expected_img = np.array([[204, 153], [102, 51]], dtype=np.uint8)
        output_img = sw_luadocs.recognize.preprocess_image(input_img)
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
        output_img = sw_luadocs.recognize.preprocess_image(input_img)
        self.assertTrue(np.array_equal(output_img, expected_img))


class TestCategorizeLine(unittest.TestCase):
    def test_validate_ok(self):
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.zeros((1, 1, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=0,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "code")

    def test_validate_conv(self):
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.full((1, 2, 4), 255, dtype=np.uint8),
            head_thresh_s="0",
            code_thresh_x="1",
            bg_thresh_rgb=("0", "0", "0"),
        )
        self.assertEqual(kind, "head")

    def test_validate_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.recognize.categorize_line(
                tessline=None,
                capture_img=np.zeros((1, 1, 3), dtype=np.uint8),
                head_thresh_s=0,
                code_thresh_x=0,
                bg_thresh_rgb=(0, 0, 0),
            )

    def test_validate_value(self):
        for kwargs in [
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(1, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 1, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 2, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 2)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((0, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 0, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": -1,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 256,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": -1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (-1, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (256, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, -1, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 256, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, -1),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "bg_thresh_rgb": (0, 0, 256),
            },
        ]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    sw_luadocs.recognize.categorize_line(**kwargs)

    def test_code(self):
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.zeros((1, 1, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=0,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "code")

    def test_crop_1(self):
        capture_img = np.zeros((10, 10), dtype=np.uint8)
        capture_img[3, 2] = 1
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(2, 3, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=0,
            code_thresh_x=3,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

    def test_crop_2(self):
        capture_img = np.zeros((10, 10), dtype=np.uint8)
        capture_img[0, 1] = 1
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 2, 1)),
            capture_img=capture_img,
            head_thresh_s=0,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

    def test_crop_3(self):
        capture_img = np.zeros((10, 10), dtype=np.uint8)
        capture_img[2, 0] = 1
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 3)),
            capture_img=capture_img,
            head_thresh_s=0,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

    def test_thresh_none(self):
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.full((2, 2, 3), 255, dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=1,
            bg_thresh_rgb=(255, 255, 255),
        )
        self.assertEqual(kind, "body")

    def test_thresh_r(self):
        capture_img = np.zeros((2, 2, 3), dtype=np.uint8)
        capture_img[:, :, 0] = 3
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=0,
            code_thresh_x=1,
            bg_thresh_rgb=(2, 255, 255),
        )
        self.assertEqual(kind, "head")

    def test_thresh_g(self):
        capture_img = np.zeros((2, 2, 3), dtype=np.uint8)
        capture_img[:, :, 1] = 3
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=0,
            code_thresh_x=1,
            bg_thresh_rgb=(255, 2, 255),
        )
        self.assertEqual(kind, "head")

    def test_thresh_b(self):
        capture_img = np.zeros((2, 2, 3), dtype=np.uint8)
        capture_img[:, :, 2] = 3
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=0,
            code_thresh_x=1,
            bg_thresh_rgb=(255, 255, 2),
        )
        self.assertEqual(kind, "head")

    def test_mask_all(self):
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.zeros((2, 2, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=1,
            bg_thresh_rgb=(255, 255, 255),
        )
        self.assertEqual(kind, "body")

    def test_mask_part(self):
        capture_img = np.zeros((2, 2, 3), dtype=np.uint8)
        capture_img[0, 0, 0] = 255
        capture_img[0, 0, 1] = 0
        capture_img[0, 0, 2] = 0
        capture_img[0, 1, 0] = 0
        capture_img[0, 1, 1] = 255
        capture_img[0, 1, 2] = 255
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 2, 1)),
            capture_img=capture_img,
            head_thresh_s=1,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "body")

    def test_saturation_zero(self):
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.full((2, 2, 3), 1, dtype=np.uint8),
            head_thresh_s=1,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "body")

    def test_saturation_r(self):
        capture_img = np.zeros((2, 2, 3), dtype=np.uint8)
        capture_img[:, :, 0] = 1
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=255,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

    def test_saturation_g(self):
        capture_img = np.zeros((2, 2, 3), dtype=np.uint8)
        capture_img[:, :, 1] = 1
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=255,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

    def test_saturation_b(self):
        capture_img = np.zeros((2, 2, 3), dtype=np.uint8)
        capture_img[:, :, 2] = 1
        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=255,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

    def test_saturation_normal(self):
        capture_img = np.zeros((2, 2, 3), dtype=np.uint8)
        capture_img[:, :, 0] = 83
        capture_img[:, :, 1] = 59
        capture_img[:, :, 2] = 63

        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=43,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "head")

        kind = sw_luadocs.recognize.categorize_line(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=capture_img,
            head_thresh_s=44,
            code_thresh_x=1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(kind, "body")


class TestCalcCharCount(unittest.TestCase):
    def test_type(self):
        cnt = sw_luadocs.recognize.calc_char_count(
            pos1="12", pos2="34", size="0.5", vmin="0"
        )
        self.assertEqual(cnt, 44)

    def test_validate_pass(self):
        cnt = sw_luadocs.recognize.calc_char_count(pos1=0, pos2=0, size=0.1, vmin=0)
        self.assertEqual(cnt, 0)

    def test_validate_error(self):
        for kwargs in [
            {"pos1": -1, "pos2": 0, "size": 0.1, "vmin": 0},
            {"pos1": 0, "pos2": -1, "size": 0.1, "vmin": 0},
            {"pos1": 0, "pos2": 0, "size": float("nan"), "vmin": 0},
            {"pos1": 0, "pos2": 0, "size": 0, "vmin": 0},
        ]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    sw_luadocs.recognize.calc_char_count(**kwargs)

    def test_normal(self):
        cnt = sw_luadocs.recognize.calc_char_count(pos1=12, pos2=34, size=0.5, vmin=0)
        self.assertEqual(cnt, 44)

    def test_round(self):
        cnt = sw_luadocs.recognize.calc_char_count(pos1=12, pos2=34, size=3, vmin=0)
        self.assertEqual(cnt, 7)

    def test_vmin(self):
        cnt = sw_luadocs.recognize.calc_char_count(pos1=12, pos2=34, size=0.5, vmin=45)
        self.assertEqual(cnt, 45)


class TestGroupOCRLine(unittest.TestCase):
    def test_type(self):
        def ocrline_gen():
            yield sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1))
            yield sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1))
            yield sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1))

        sl_list = sw_luadocs.recognize.group_ocrline(ocrline_gen())
        self.assertEqual(sl_list, [slice(0, 1), slice(1, 2), slice(2, 3)])

    def test_empty(self):
        sl_list = sw_luadocs.recognize.group_ocrline([])
        self.assertEqual(sl_list, [])

    def test_single(self):
        sl_list = sw_luadocs.recognize.group_ocrline(
            [sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1))]
        )
        self.assertEqual(sl_list, [slice(0, 1)])

    def test_diffkind(self):
        sl_list = sw_luadocs.recognize.group_ocrline(
            [
                sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1)),
            ]
        )
        self.assertEqual(sl_list, [slice(0, 1), slice(1, 2), slice(2, 3)])

    def test_samekind(self):
        sl_list = sw_luadocs.recognize.group_ocrline(
            [
                sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1)),
            ]
        )
        self.assertEqual(sl_list, [slice(0, 2), slice(2, 4), slice(4, 6)])


class TestConvertTessTSVToTessline(unittest.TestCase):
    def test_type(self):
        with self.assertRaises(ValueError):
            sw_luadocs.recognize.convert_tesstsv_to_tessline(
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

    def test_combine(self):
        for input_tesstsv, expected_tessline_list in [
            (
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
                [sw_luadocs.recognize.TesseractLine(txt="", box=(10, 11, 12, 13))],
            ),
            (
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
                    sw_luadocs.recognize.TesseractLine(txt="", box=(4, 4, 4, 4)),
                    sw_luadocs.recognize.TesseractLine(txt="", box=(6, 6, 6, 6)),
                ],
            ),
            (
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
                [sw_luadocs.recognize.TesseractLine(txt="5", box=(4, 4, 4, 4))],
            ),
            (
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
                [sw_luadocs.recognize.TesseractLine(txt="5 6", box=(4, 4, 4, 4))],
            ),
            (
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
                [sw_luadocs.recognize.TesseractLine(txt="2 4", box=(1, 1, 1, 1))],
            ),
            (
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
                    sw_luadocs.recognize.TesseractLine(txt="2", box=(1, 1, 1, 1)),
                    sw_luadocs.recognize.TesseractLine(txt="5", box=(4, 4, 4, 4)),
                ],
            ),
            (
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
                    sw_luadocs.recognize.TesseractLine(
                        txt="Multiply two matrices together.",
                        box=(2, 10, 273, 19),
                    ),
                    sw_luadocs.recognize.TesseractLine(
                        txt="out_matrix = matrix.multiply(matrixl, matrix2)",
                        box=(14, 34, 432, 16),
                    ),
                    sw_luadocs.recognize.TesseractLine(
                        txt="Invert a matrix.",
                        box=(1, 70, 133, 14),
                    ),
                    sw_luadocs.recognize.TesseractLine(
                        txt="out_matrix = matrix.invert(matrix1)",
                        box=(14, 93, 328, 16),
                    ),
                ],
            ),
        ]:
            with self.subTest(input_tesstsv=input_tesstsv):
                output_tessline_list = sw_luadocs.recognize.convert_tesstsv_to_tessline(
                    input_tesstsv
                )
                self.assertEqual(output_tessline_list, expected_tessline_list)


class TestConvertTesslineToOCRLine(unittest.TestCase):
    def test_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.recognize.convert_tessline_to_ocrline(
                tessline=None,
                capture_img=np.zeros((1, 1, 3), dtype=np.uint8),
                head_thresh_s=0,
                code_thresh_x=0,
                code_base_x=0,
                code_indent_w=1,
                bg_thresh_rgb=(0, 0, 0),
            )

    def test_type_normalize(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.zeros((1, 1), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x="0",
            code_base_x="0",
            code_indent_w="0.1",
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline, sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1))
        )

    def test_validate_pass(self):
        for kwargs in [
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "code_base_x": 0,
                "code_indent_w": 0.1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 2, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 1,
                "code_base_x": 1,
                "code_indent_w": 0.1,
                "bg_thresh_rgb": (0, 0, 0),
            },
        ]:
            with self.subTest(kwargs=kwargs):
                sw_luadocs.recognize.convert_tessline_to_ocrline(**kwargs)

    def test_validate_error(self):
        for kwargs in [
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((0, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "code_base_x": 0,
                "code_indent_w": 1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 0, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "code_base_x": 0,
                "code_indent_w": 1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": -1,
                "code_base_x": 0,
                "code_indent_w": 1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 1,
                "code_base_x": 0,
                "code_indent_w": 1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "code_base_x": -1,
                "code_indent_w": 1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "code_base_x": 1,
                "code_indent_w": 1,
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "code_base_x": 0,
                "code_indent_w": float("nan"),
                "bg_thresh_rgb": (0, 0, 0),
            },
            {
                "tessline": sw_luadocs.recognize.TesseractLine(
                    txt="", box=(0, 0, 1, 1)
                ),
                "capture_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "head_thresh_s": 0,
                "code_thresh_x": 0,
                "code_base_x": 0,
                "code_indent_w": 0,
                "bg_thresh_rgb": (0, 0, 0),
            },
        ]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    sw_luadocs.recognize.convert_tessline_to_ocrline(**kwargs)

    def test_indent_head(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(1, 0, 1, 1)),
            capture_img=np.full((1, 4, 3), 255, dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=2,
            code_base_x=3,
            code_indent_w=0.1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline, sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(1, 0, 1, 1))
        )

    def test_indent_body(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(1, 0, 1, 1)),
            capture_img=np.zeros((1, 4, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=2,
            code_base_x=3,
            code_indent_w=0.1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline, sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(1, 0, 1, 1))
        )

    def test_indent_code(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(1, 0, 1, 1)),
            capture_img=np.zeros((1, 2, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=0,
            code_base_x=0,
            code_indent_w=0.1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline,
            sw_luadocs.recognize.OCRLine(txt="\t" * 10, kind="code", box=(1, 0, 1, 1)),
        )

    def test_kind_head(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.full((1, 3, 3), 255, dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=1,
            code_base_x=2,
            code_indent_w=0.1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline, sw_luadocs.recognize.OCRLine(txt="", kind="head", box=(0, 0, 1, 1))
        )

    def test_kind_body(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.zeros((1, 3, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=1,
            code_base_x=2,
            code_indent_w=0.1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline, sw_luadocs.recognize.OCRLine(txt="", kind="body", box=(0, 0, 1, 1))
        )

    def test_kind_code(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(0, 0, 1, 1)),
            capture_img=np.zeros((1, 1, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=0,
            code_base_x=0,
            code_indent_w=0.1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline, sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(0, 0, 1, 1))
        )

    def test_txt(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="abc", box=(0, 0, 1, 1)),
            capture_img=np.zeros((1, 1, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=0,
            code_base_x=0,
            code_indent_w=0.1,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline,
            sw_luadocs.recognize.OCRLine(txt="abc", kind="code", box=(0, 0, 1, 1)),
        )

    def test_box(self):
        ocrline = sw_luadocs.recognize.convert_tessline_to_ocrline(
            tessline=sw_luadocs.recognize.TesseractLine(txt="", box=(10, 11, 12, 13)),
            capture_img=np.zeros((100, 100, 3), dtype=np.uint8),
            head_thresh_s=0,
            code_thresh_x=0,
            code_base_x=0,
            code_indent_w=100,
            bg_thresh_rgb=(0, 0, 0),
        )
        self.assertEqual(
            ocrline,
            sw_luadocs.recognize.OCRLine(txt="", kind="code", box=(10, 11, 12, 13)),
        )


class TestConvertOCRLineToFlatDocIndividual(unittest.TestCase):
    def test_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.recognize.convert_ocrline_to_flatdoc_individual([None])

    def test_empty(self):
        flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc_individual([])
        self.assertEqual(flatdoc, [])

    def test_convert(self):
        flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc_individual(
            [
                sw_luadocs.recognize.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="b", kind="body", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="c", kind="code", box=(0, 0, 1, 1)),
            ]
        )
        self.assertEqual(
            flatdoc,
            [
                sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                sw_luadocs.flatdoc.FlatElem(txt="b", kind="body"),
                sw_luadocs.flatdoc.FlatElem(txt="c", kind="code"),
            ],
        )


class TestConvertOCRLineToFlatDocPack(unittest.TestCase):
    def test_validate_type_error(self):
        with self.assertRaises(TypeError):
            sw_luadocs.recognize.convert_ocrline_to_flatdoc_pack([None], line_h=0.1)

    def test_main(self):
        for (input_ocrline_list, input_line_h, expected_flatdoc) in [
            ([], 0.1, []),
            (
                [sw_luadocs.recognize.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1))],
                0.1,
                [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")],
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="b", kind="body", box=(0, 0, 1, 1))],
                0.1,
                [sw_luadocs.flatdoc.FlatElem(txt="b", kind="body")],
            ),
            (
                [sw_luadocs.recognize.OCRLine(txt="c", kind="code", box=(0, 0, 1, 1))],
                0.1,
                [sw_luadocs.flatdoc.FlatElem(txt="c", kind="code")],
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="head", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="head", box=(0, 1, 1, 1)
                    ),
                ],
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="head")],
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="body", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="body", box=(0, 1, 1, 1)
                    ),
                ],
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="body")],
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="code", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="code", box=(0, 1, 1, 1)
                    ),
                ],
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="code")],
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="code", box=(0, 1, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="code", box=(0, 3, 1, 1)
                    ),
                ],
                0.5,
                [sw_luadocs.flatdoc.FlatElem(txt="a\n\n\n\nb", kind="code")],
            ),
            (
                [
                    sw_luadocs.recognize.OCRLine(
                        txt="a", kind="code", box=(0, 0, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="b", kind="code", box=(0, 1, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="c", kind="code", box=(0, 3, 1, 1)
                    ),
                    sw_luadocs.recognize.OCRLine(
                        txt="d", kind="code", box=(0, 6, 1, 1)
                    ),
                ],
                1,
                [sw_luadocs.flatdoc.FlatElem(txt="a\nb\n\nc\n\n\nd", kind="code")],
            ),
        ]:
            with self.subTest(ocrline_list=input_ocrline_list, line_h=input_line_h):
                actual_flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc_pack(
                    input_ocrline_list, line_h=input_line_h
                )
                self.assertEqual(actual_flatdoc, expected_flatdoc)


class TestConvertOCRLineToFlatDocMonoKind(unittest.TestCase):
    def test_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.recognize.convert_ocrline_to_flatdoc_monokind(
                [None], body_line_h=0.1, code_line_h=0.1
            )

    def test_empty(self):
        flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc_monokind(
            [], body_line_h=0.1, code_line_h=0.1
        )
        self.assertEqual(flatdoc, [])

    def test_head(self):
        flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc_monokind(
            [sw_luadocs.recognize.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1))],
            body_line_h=0.1,
            code_line_h=0.1,
        )
        self.assertEqual(flatdoc, [sw_luadocs.flatdoc.FlatElem(txt="a", kind="head")])

    def test_body(self):
        flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc_monokind(
            [
                sw_luadocs.recognize.OCRLine(txt="a", kind="body", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="b", kind="body", box=(0, 1, 1, 1)),
            ],
            body_line_h=10,
            code_line_h=0.1,
        )
        self.assertEqual(
            flatdoc, [sw_luadocs.flatdoc.FlatElem(txt="a\nb", kind="body")]
        )

    def test_code(self):
        flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc_monokind(
            [
                sw_luadocs.recognize.OCRLine(txt="a", kind="code", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="b", kind="code", box=(0, 1, 1, 1)),
            ],
            body_line_h=10,
            code_line_h=0.1,
        )
        self.assertEqual(
            flatdoc,
            [sw_luadocs.flatdoc.FlatElem(txt="a\n\n\n\n\n\n\n\n\n\nb", kind="code")],
        )


class TestConvertOCRLineToFlatDoc(unittest.TestCase):
    def test_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.recognize.convert_ocrline_to_flatdoc(
                [None], body_line_h=0.1, code_line_h=0.1
            )

    def test_empty(self):
        flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc(
            [], body_line_h=0.1, code_line_h=0.1
        )
        self.assertEqual(flatdoc, [])

    def test_normal(self):
        flatdoc = sw_luadocs.recognize.convert_ocrline_to_flatdoc(
            [
                sw_luadocs.recognize.OCRLine(txt="a", kind="head", box=(0, 0, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="b", kind="body", box=(0, 1, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="c", kind="body", box=(0, 2, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="d", kind="code", box=(0, 3, 1, 1)),
                sw_luadocs.recognize.OCRLine(txt="e", kind="code", box=(0, 4, 1, 1)),
            ],
            body_line_h=0.5,
            code_line_h=1,
        )
        self.assertEqual(
            flatdoc,
            [
                sw_luadocs.flatdoc.FlatElem(txt="a", kind="head"),
                sw_luadocs.flatdoc.FlatElem(txt="b\n\nc", kind="body"),
                sw_luadocs.flatdoc.FlatElem(txt="d\ne", kind="code"),
            ],
        )
