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


class TestSplitImageIntoPieces(unittest.TestCase):
    def test_invalid_value(self):
        for capture_img, fg_mergin_h, bg_thresh_rgb in [
            (np.zeros((0, 0), dtype=np.uint8), -1, (0, 0, 0)),
            (np.zeros((0, 0), dtype=np.uint8), 0, (-1, 0, 0)),
            (np.zeros((0, 0), dtype=np.uint8), 0, (256, 0, 0)),
            (np.zeros((0, 0), dtype=np.uint8), 0, (0, -1, 0)),
            (np.zeros((0, 0), dtype=np.uint8), 0, (0, 256, 0)),
            (np.zeros((0, 0), dtype=np.uint8), 0, (0, 0, -1)),
            (np.zeros((0, 0), dtype=np.uint8), 0, (0, 0, 256)),
        ]:
            with self.subTest(
                capture_img=capture_img,
                fg_mergin_h=fg_mergin_h,
                bg_thresh_rgb=bg_thresh_rgb,
            ):
                with self.assertRaises(ValueError):
                    sw_luadocs.imgdiff.split_image_into_pieces(
                        capture_img,
                        fg_mergin_h=fg_mergin_h,
                        bg_thresh_rgb=bg_thresh_rgb,
                    )

    def test_main(self):
        for (
            input_capture_img,
            input_fg_mergin_h,
            input_bg_thresh_rgb,
            expected_ipc_list,
        ) in [
            (np.zeros((0, 0), dtype=np.uint8), 0, (0, 0, 0), []),
            (
                np.array([[[127, 127, 127]]], dtype=np.uint8),
                0,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[127, 127, 127]]], dtype=np.uint8), is_fg=False
                    )
                ],
            ),
            (
                np.array([[[128, 127, 127]]], dtype=np.uint8),
                0,
                (127, 255, 255),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[128, 127, 127]]], dtype=np.uint8), is_fg=True
                    )
                ],
            ),
            (
                np.array([[[127, 128, 127]]], dtype=np.uint8),
                0,
                (255, 127, 255),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[127, 128, 127]]], dtype=np.uint8), is_fg=True
                    )
                ],
            ),
            (
                np.array([[[127, 127, 128]]], dtype=np.uint8),
                0,
                (255, 255, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[127, 127, 128]]], dtype=np.uint8), is_fg=True
                    )
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127], [127, 127, 127], [127, 127, 127]]],
                    dtype=np.uint8,
                ),
                0,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127], [127, 127, 127], [127, 127, 127]]],
                            dtype=np.uint8,
                        ),
                        is_fg=False,
                    )
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127], [127, 127, 127], [128, 127, 127]]],
                    dtype=np.uint8,
                ),
                0,
                (127, 255, 255),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127], [127, 127, 127], [128, 127, 127]]],
                            dtype=np.uint8,
                        ),
                        is_fg=True,
                    )
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127], [127, 127, 127], [127, 128, 127]]],
                    dtype=np.uint8,
                ),
                0,
                (255, 127, 255),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127], [127, 127, 127], [127, 128, 127]]],
                            dtype=np.uint8,
                        ),
                        is_fg=True,
                    )
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127], [127, 127, 127], [127, 127, 128]]],
                    dtype=np.uint8,
                ),
                0,
                (255, 255, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127], [127, 127, 127], [127, 127, 128]]],
                            dtype=np.uint8,
                        ),
                        is_fg=True,
                    )
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127]], [[127, 127, 127]], [[127, 127, 127]]],
                    dtype=np.uint8,
                ),
                0,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127]], [[127, 127, 127]], [[127, 127, 127]]],
                            dtype=np.uint8,
                        ),
                        is_fg=False,
                    )
                ],
            ),
            (
                np.array(
                    [[[128, 128, 128]], [[127, 127, 127]], [[127, 127, 127]]],
                    dtype=np.uint8,
                ),
                0,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[128, 128, 128]]], dtype=np.uint8),
                        is_fg=True,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127]], [[127, 127, 127]]], dtype=np.uint8
                        ),
                        is_fg=False,
                    ),
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127]], [[128, 128, 128]], [[127, 127, 127]]],
                    dtype=np.uint8,
                ),
                0,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[127, 127, 127]]], dtype=np.uint8),
                        is_fg=False,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[128, 128, 128]]], dtype=np.uint8),
                        is_fg=True,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[127, 127, 127]]], dtype=np.uint8),
                        is_fg=False,
                    ),
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127]], [[127, 127, 127]], [[128, 128, 128]]],
                    dtype=np.uint8,
                ),
                0,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127]], [[127, 127, 127]]], dtype=np.uint8
                        ),
                        is_fg=False,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[128, 128, 128]]], dtype=np.uint8),
                        is_fg=True,
                    ),
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127]], [[127, 127, 127]], [[127, 127, 127]]],
                    dtype=np.uint8,
                ),
                2,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127]], [[127, 127, 127]], [[127, 127, 127]]],
                            dtype=np.uint8,
                        ),
                        is_fg=False,
                    )
                ],
            ),
            (
                np.array(
                    [[[127, 127, 127]], [[127, 127, 127]], [[127, 127, 127]]],
                    dtype=np.uint8,
                ),
                3,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127]], [[127, 127, 127]], [[127, 127, 127]]],
                            dtype=np.uint8,
                        ),
                        is_fg=True,
                    )
                ],
            ),
            (
                np.array(
                    [
                        [[128, 128, 128]],
                        [[128, 128, 128]],
                        [[127, 127, 127]],
                        [[127, 127, 127]],
                        [[127, 127, 127]],
                        [[128, 128, 128]],
                        [[128, 128, 128]],
                    ],
                    dtype=np.uint8,
                ),
                2,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[128, 128, 128]], [[128, 128, 128]]], dtype=np.uint8
                        ),
                        is_fg=True,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[127, 127, 127]], [[127, 127, 127]], [[127, 127, 127]]],
                            dtype=np.uint8,
                        ),
                        is_fg=False,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[128, 128, 128]], [[128, 128, 128]]], dtype=np.uint8
                        ),
                        is_fg=True,
                    ),
                ],
            ),
            (
                np.array(
                    [
                        [[128, 128, 128]],
                        [[128, 128, 128]],
                        [[127, 127, 127]],
                        [[127, 127, 127]],
                        [[127, 127, 127]],
                        [[128, 128, 128]],
                        [[128, 128, 128]],
                    ],
                    dtype=np.uint8,
                ),
                3,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [
                                [[128, 128, 128]],
                                [[128, 128, 128]],
                                [[127, 127, 127]],
                                [[127, 127, 127]],
                                [[127, 127, 127]],
                                [[128, 128, 128]],
                                [[128, 128, 128]],
                            ],
                            dtype=np.uint8,
                        ),
                        is_fg=True,
                    ),
                ],
            ),
            (
                np.array(
                    [
                        [[127, 127, 127]],
                        [[128, 128, 128]],
                        [[127, 127, 127]],
                        [[128, 128, 128]],
                        [[127, 127, 127]],
                    ],
                    dtype=np.uint8,
                ),
                0,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[127, 127, 127]]], dtype=np.uint8),
                        is_fg=False,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[128, 128, 128]]], dtype=np.uint8),
                        is_fg=True,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[127, 127, 127]]], dtype=np.uint8),
                        is_fg=False,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[128, 128, 128]]], dtype=np.uint8),
                        is_fg=True,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array([[[127, 127, 127]]], dtype=np.uint8),
                        is_fg=False,
                    ),
                ],
            ),
            (
                np.array(
                    [
                        [[127, 127, 127]],
                        [[128, 128, 128]],
                        [[127, 127, 127]],
                        [[128, 128, 128]],
                        [[127, 127, 127]],
                    ],
                    dtype=np.uint8,
                ),
                1,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [
                                [[127, 127, 127]],
                                [[128, 128, 128]],
                                [[127, 127, 127]],
                                [[128, 128, 128]],
                                [[127, 127, 127]],
                            ],
                            dtype=np.uint8,
                        ),
                        is_fg=True,
                    ),
                ],
            ),
            (
                np.array(
                    [
                        [[0, 1, 2], [3, 4, 5]],
                        [[128, 129, 130], [131, 132, 133]],
                        [[6, 7, 8], [9, 10, 11]],
                        [[12, 13, 14], [15, 16, 17]],
                        [[18, 19, 20], [21, 22, 23]],
                        [[134, 135, 136], [137, 138, 139]],
                        [[140, 141, 142], [143, 144, 145]],
                        [[146, 147, 148], [149, 150, 151]],
                        [[152, 153, 154], [155, 156, 157]],
                    ],
                    dtype=np.uint8,
                ),
                0,
                (127, 127, 127),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[0, 1, 2], [3, 4, 5]]],
                            dtype=np.uint8,
                        ),
                        is_fg=False,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [[[128, 129, 130], [131, 132, 133]]],
                            dtype=np.uint8,
                        ),
                        is_fg=True,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [
                                [[6, 7, 8], [9, 10, 11]],
                                [[12, 13, 14], [15, 16, 17]],
                                [[18, 19, 20], [21, 22, 23]],
                            ],
                            dtype=np.uint8,
                        ),
                        is_fg=False,
                    ),
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.array(
                            [
                                [[134, 135, 136], [137, 138, 139]],
                                [[140, 141, 142], [143, 144, 145]],
                                [[146, 147, 148], [149, 150, 151]],
                                [[152, 153, 154], [155, 156, 157]],
                            ],
                            dtype=np.uint8,
                        ),
                        is_fg=True,
                    ),
                ],
            ),
            (
                np.zeros((1, 2), dtype=np.uint8),
                "0",
                ("127", "127", "127"),
                [
                    sw_luadocs.imgdiff.ImagePiece(
                        img=np.zeros((1, 2, 3), dtype=np.uint8),
                        is_fg=False,
                    ),
                ],
            ),
        ]:
            with self.subTest(
                capture_img=input_capture_img,
                fg_mergin_h=input_fg_mergin_h,
                bg_thresh_rgb=input_bg_thresh_rgb,
            ):
                actual_ipc_list = sw_luadocs.imgdiff.split_image_into_pieces(
                    input_capture_img,
                    fg_mergin_h=input_fg_mergin_h,
                    bg_thresh_rgb=input_bg_thresh_rgb,
                )
                self.assertEqual(actual_ipc_list, expected_ipc_list)
