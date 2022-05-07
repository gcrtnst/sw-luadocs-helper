import copy
import sw_luadocs_ocr.ocr
import unittest


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
