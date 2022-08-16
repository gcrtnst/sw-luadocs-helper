import numpy as np
import sw_luadocs.imgdiff
import unittest


class TestImagePieceInit(unittest.TestCase):
    def test_invalid_value(self):
        with self.assertRaises(ValueError):
            sw_luadocs.imgdiff.ImagePiece(
                img=np.zeros((0, 0), dtype=np.uint8), is_fg=True
            )

    def test_main(self):
        for input_img, input_is_blank, expected_img, expected_is_fg in [
            (
                np.array(
                    [
                        [
                            [0, 1, 2],
                            [10, 11, 12],
                            [20, 21, 22],
                            [30, 31, 32],
                        ],
                        [
                            [100, 101, 102],
                            [110, 111, 112],
                            [120, 121, 122],
                            [130, 131, 132],
                        ],
                        [
                            [200, 201, 202],
                            [210, 211, 212],
                            [220, 221, 222],
                            [230, 231, 232],
                        ],
                    ],
                    dtype=np.uint8,
                ),
                False,
                np.array(
                    [
                        [
                            [0, 1, 2],
                            [10, 11, 12],
                            [20, 21, 22],
                            [30, 31, 32],
                        ],
                        [
                            [100, 101, 102],
                            [110, 111, 112],
                            [120, 121, 122],
                            [130, 131, 132],
                        ],
                        [
                            [200, 201, 202],
                            [210, 211, 212],
                            [220, 221, 222],
                            [230, 231, 232],
                        ],
                    ],
                    dtype=np.uint8,
                ),
                False,
            ),
            (
                np.array(
                    [
                        [
                            [0, 1, 2],
                            [10, 11, 12],
                            [20, 21, 22],
                            [30, 31, 32],
                        ],
                        [
                            [100, 101, 102],
                            [110, 111, 112],
                            [120, 121, 122],
                            [130, 131, 132],
                        ],
                        [
                            [200, 201, 202],
                            [210, 211, 212],
                            [220, 221, 222],
                            [230, 231, 232],
                        ],
                    ],
                    dtype=np.uint8,
                ),
                True,
                np.array(
                    [
                        [
                            [0, 1, 2],
                            [10, 11, 12],
                            [20, 21, 22],
                            [30, 31, 32],
                        ],
                        [
                            [100, 101, 102],
                            [110, 111, 112],
                            [120, 121, 122],
                            [130, 131, 132],
                        ],
                        [
                            [200, 201, 202],
                            [210, 211, 212],
                            [220, 221, 222],
                            [230, 231, 232],
                        ],
                    ],
                    dtype=np.uint8,
                ),
                True,
            ),
            (
                np.array(
                    [
                        [0, 10, 20, 30],
                        [100, 110, 120, 130],
                        [200, 210, 220, 230],
                    ],
                    dtype=np.uint8,
                ),
                "",
                np.array(
                    [
                        [
                            [0, 0, 0],
                            [10, 10, 10],
                            [20, 20, 20],
                            [30, 30, 30],
                        ],
                        [
                            [100, 100, 100],
                            [110, 110, 110],
                            [120, 120, 120],
                            [130, 130, 130],
                        ],
                        [
                            [200, 200, 200],
                            [210, 210, 210],
                            [220, 220, 220],
                            [230, 230, 230],
                        ],
                    ],
                    dtype=np.uint8,
                ),
                False,
            ),
        ]:
            with self.subTest(img=input_img, is_fg=input_is_blank):
                actual_ipc = sw_luadocs.imgdiff.ImagePiece(
                    img=input_img, is_fg=input_is_blank
                )
                self.assertTrue(np.array_equal(actual_ipc._img, expected_img))
                self.assertFalse(np.shares_memory(actual_ipc._img, input_img))
                self.assertTrue(actual_ipc._img.flags.c_contiguous)
                self.assertFalse(actual_ipc._img.flags.writeable)
                self.assertEqual(actual_ipc._is_fg, expected_is_fg)


class TestImagePieceEq(unittest.TestCase):
    def test_main(self):
        for input_self, input_other, expected_result in [
            (
                sw_luadocs.imgdiff.ImagePiece(
                    img=np.zeros((1, 1), dtype=np.uint8), is_fg=False
                ),
                None,
                False,
            ),
            (
                sw_luadocs.imgdiff.ImagePiece(
                    img=np.zeros((1, 1), dtype=np.uint8), is_fg=False
                ),
                sw_luadocs.imgdiff.ImagePiece(
                    img=np.ones((1, 1), dtype=np.uint8), is_fg=False
                ),
                False,
            ),
            (
                sw_luadocs.imgdiff.ImagePiece(
                    img=np.zeros((1, 1), dtype=np.uint8), is_fg=False
                ),
                sw_luadocs.imgdiff.ImagePiece(
                    img=np.zeros((1, 1), dtype=np.uint8), is_fg=True
                ),
                False,
            ),
            (
                sw_luadocs.imgdiff.ImagePiece(
                    img=np.zeros((1, 1), dtype=np.uint8), is_fg=False
                ),
                sw_luadocs.imgdiff.ImagePiece(
                    img=np.zeros((1, 1), dtype=np.uint8), is_fg=False
                ),
                True,
            ),
        ]:
            with self.subTest(_self=input_self, other=input_other):
                actual_result = input_self == input_other
                self.assertEqual(actual_result, expected_result)
