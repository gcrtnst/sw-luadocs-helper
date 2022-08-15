import numpy as np
import sw_luadocs.imgdiff
import unittest


class TestImagePiecePostInit(unittest.TestCase):
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
                self.assertTrue(np.array_equal(actual_ipc.img, expected_img))
                self.assertEqual(actual_ipc.is_fg, expected_is_fg)
