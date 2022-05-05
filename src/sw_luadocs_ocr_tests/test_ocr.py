import unittest
import sw_luadocs_ocr.ocr


class TestOCR(unittest.TestCase):
    def test_parse_tesseract_data(self):
        # wrong type
        data = []
        with self.assertRaises(TypeError):
            sw_luadocs_ocr.ocr.parse_tesseract_data(data)

        # missing "level" in data
        data = {"left": [], "top": [], "width": [], "height": [], "text": []}
        with self.assertRaises(KeyError):
            sw_luadocs_ocr.ocr.parse_tesseract_data(data)

        # missing "left" in data
        data = {"level": [], "top": [], "width": [], "height": [], "text": []}
        with self.assertRaises(KeyError):
            sw_luadocs_ocr.ocr.parse_tesseract_data(data)

        # missing "top" in data
        data = {"level": [], "left": [], "width": [], "height": [], "text": []}
        with self.assertRaises(KeyError):
            sw_luadocs_ocr.ocr.parse_tesseract_data(data)

        # missing "width" in data
        data = {"level": [], "left": [], "top": [], "height": [], "text": []}
        with self.assertRaises(KeyError):
            sw_luadocs_ocr.ocr.parse_tesseract_data(data)

        # missing "height" in data
        data = {"level": [], "left": [], "top": [], "width": [], "text": []}
        with self.assertRaises(KeyError):
            sw_luadocs_ocr.ocr.parse_tesseract_data(data)

        # missing "text" in data
        data = {"level": [], "left": [], "top": [], "width": [], "height": []}
        with self.assertRaises(KeyError):
            sw_luadocs_ocr.ocr.parse_tesseract_data(data)

        # no data
        data = {
            "level": [],
            "left": [],
            "top": [],
            "width": [],
            "height": [],
            "text": [],
        }
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(line_list, [])

        # no line
        data = {
            "level": [1, 2, 3, 5],
            "left": [0, 0, 0, 0],
            "top": [0, 0, 0, 0],
            "width": [0, 0, 0, 0],
            "height": [0, 0, 0, 0],
            "text": ["", "", "", ""],
        }
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(line_list, [])

        # line only
        data = {
            "level": [4],
            "left": [0],
            "top": [1],
            "width": [2],
            "height": [3],
            "text": ["text"],
        }
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(line_list, [{"txt": "", "box": (0, 1, 2, 3)}])

        # line and other
        data = {
            "level": [1, 2, 3, 4, 3, 4],
            "left": [1, 2, 3, 4, 5, 6],
            "top": [1, 2, 3, 4, 5, 6],
            "width": [1, 2, 3, 4, 5, 6],
            "height": [1, 2, 3, 4, 5, 6],
            "text": ["1", "2", "3", "4", "5", "6"],
        }
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(
            line_list,
            [{"txt": "", "box": (4, 4, 4, 4)}, {"txt": "", "box": (6, 6, 6, 6)}],
        )

        # single text only
        data = {
            "level": [4, 5],
            "left": [4, 5],
            "top": [4, 5],
            "width": [4, 5],
            "height": [4, 5],
            "text": ["4", "5"],
        }
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(line_list, [{"txt": "5", "box": (4, 4, 4, 4)}])

        # multiple text only
        data = {
            "level": [4, 5, 5],
            "left": [4, 5, 6],
            "top": [4, 5, 6],
            "width": [4, 5, 6],
            "height": [4, 5, 6],
            "text": ["4", "5", "6"],
        }
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(line_list, [{"txt": "5 6", "box": (4, 4, 4, 4)}])

        # multiple text and other
        data = {
            "level": [4, 5, 6, 5],
            "left": [1, 2, 3, 4],
            "top": [1, 2, 3, 4],
            "width": [1, 2, 3, 4],
            "height": [1, 2, 3, 4],
            "text": ["1", "2", "3", "4"],
        }
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(line_list, [{"txt": "2 4", "box": (1, 1, 1, 1)}])

        # line and text
        data = {
            "level": [4, 5, 3, 4, 5],
            "left": [1, 2, 3, 4, 5],
            "top": [1, 2, 3, 4, 5],
            "width": [1, 2, 3, 4, 5],
            "height": [1, 2, 3, 4, 5],
            "text": ["1", "2", "3", "4", "5"],
        }
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(
            line_list,
            [{"txt": "2", "box": (1, 1, 1, 1)}, {"txt": "5", "box": (4, 4, 4, 4)}],
        )

        data = {
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
                13,
                13,
                13,
                13,
                16,
                16,
                13,
                37,
                37,
                37,
                42,
                37,
                37,
                73,
                73,
                76,
                75,
                96,
                96,
                97,
                101,
                96,
            ],
            "width": [
                459,
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
                126,
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
        line_list = sw_luadocs_ocr.ocr.parse_tesseract_data(data)
        self.assertEqual(
            line_list,
            [
                {"txt": "Multiply two matrices together.", "box": (2, 13, 273, 19)},
                {
                    "txt": "out_matrix = matrix.multiply(matrixl, matrix2)",
                    "box": (14, 37, 432, 16),
                },
                {
                    "txt": "Invert a matrix.",
                    "box": (1, 73, 133, 14),
                },
                {
                    "txt": "out_matrix = matrix.invert(matrix1)",
                    "box": (14, 96, 328, 16),
                },
            ],
        )
