import numpy as np
import sw_luadocs.capture
import unittest


class TestCalcScrollAmount(unittest.TestCase):
    def test_validate_convert(self):
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            np.zeros(1, dtype=int), np.zeros(1, dtype=int), template_ratio="0.25"
        )
        self.assertEqual(scroll_amount, 0)

    def test_validate_value_pass(self):
        for kwargs in [
            {
                "old_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "new_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "template_ratio": 0.25,
            },
            {
                "old_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "new_img": np.zeros((1, 1, 3), dtype=np.uint8),
                "template_ratio": 0.25,
            },
            {
                "old_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "new_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "template_ratio": 0,
            },
            {
                "old_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "new_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "template_ratio": 1,
            },
        ]:
            with self.subTest(kwargs=kwargs):
                sw_luadocs.capture.calc_scroll_amount(**kwargs)

    def test_validate_value_error(self):
        for kwargs in [
            {
                "old_img": np.zeros((0, 0, 3), dtype=np.uint8),
                "new_img": np.zeros((0, 0, 3), dtype=np.uint8),
                "template_ratio": 0.25,
            },
            {
                "old_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "new_img": np.zeros((4, 4, 3), dtype=np.uint8),
                "template_ratio": 0.25,
            },
            {
                "old_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "new_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "template_ratio": float("nan"),
            },
            {
                "old_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "new_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "template_ratio": -0.1,
            },
            {
                "old_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "new_img": np.zeros((3, 3, 3), dtype=np.uint8),
                "template_ratio": 1.1,
            },
        ]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    sw_luadocs.capture.calc_scroll_amount(**kwargs)

    def test_calc(self):
        for input_kwargs, expected_scroll_amount in [
            (
                {
                    "old_img": np.zeros((1, 1, 3), dtype=np.uint8),
                    "new_img": np.zeros((1, 1, 3), dtype=np.uint8),
                    "template_ratio": 0,
                },
                0,
            ),
            (
                {
                    "old_img": np.array([[0], [1], [0]], dtype=np.uint8),
                    "new_img": np.array([[1], [0], [1]], dtype=np.uint8),
                    "template_ratio": 0.75,
                },
                1,
            ),
            (
                {
                    "old_img": np.array([[0], [1], [0]], dtype=np.uint8),
                    "new_img": np.array([[1], [0], [1]], dtype=np.uint8),
                    "template_ratio": 1,
                },
                0,
            ),
            (
                {
                    "old_img": np.array([[0], [1], [0]], dtype=np.uint8),
                    "new_img": np.array([[1], [0], [0]], dtype=np.uint8),
                    "template_ratio": 0,
                },
                -1,
            ),
            (
                {
                    "old_img": np.array(
                        [[0, 0, 1], [0, 1, 0], [0, 1, 1]], dtype=np.uint8
                    ),
                    "new_img": np.array(
                        [[0, 1, 0], [0, 1, 1], [1, 0, 0]], dtype=np.uint8
                    ),
                    "template_ratio": 0,
                },
                -1,
            ),
        ]:
            with self.subTest(kwargs=input_kwargs):
                actual_scroll_amount = sw_luadocs.capture.calc_scroll_amount(
                    **input_kwargs
                )
                self.assertEqual(actual_scroll_amount, expected_scroll_amount)


class TestImageProcessing(unittest.TestCase):
    def test_stitch_screenshot(self):
        # scroll_threshold type conversion
        iterable = []
        template_ratio = 0.25
        scroll_threshold = "0"
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertIsNone(gen_img)

        # scroll_threshold too small
        iterable = []
        template_ratio = 0.25
        scroll_threshold = -1
        with self.assertRaisesRegex(ValueError, r"^scroll_threshold is less than 0$"):
            sw_luadocs.capture.stitch_screenshot(
                iterable,
                template_ratio=template_ratio,
                scroll_threshold=scroll_threshold,
            )

        # image type conversion
        iterable = [[[0]]]
        template_ratio = 0.25
        scroll_threshold = 0
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertIsInstance(gen_img, np.ndarray)

        # scroll_pixels is less than scroll_threshold
        img1 = np.zeros((3, 3))
        iterable = [img1, img1]
        template_ratio = 0.25
        scroll_threshold = 3
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertTrue(np.array_equal(gen_img, img1))

        # template_ratio
        img1 = np.zeros((3, 3))
        img1[1, 1] = 1
        img2 = np.zeros((3, 3))
        img2[0, 1] = 1
        img2[2, 2] = 1
        iterable = [img1, img2]
        template_ratio = 1
        scroll_threshold = 0
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertTrue(np.array_equal(gen_img, img1))

        # 2D image, scroll 1 pixel
        img0 = np.zeros((4, 3))
        img0[1, 1] = 1
        img0[3, 2] = 1
        img1 = np.zeros((3, 3))
        img1[1, 1] = 1
        img2 = np.zeros((3, 3))
        img2[0, 1] = 1
        img2[2, 2] = 1
        iterable = [img1, img2]
        template_ratio = 0
        scroll_threshold = 0
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertTrue(np.array_equal(gen_img, img0))

        # 3D image, scroll 1 pixel
        img0 = np.zeros((4, 3, 3))
        img0[1, 1, 1] = 1
        img0[3, 2, 1] = 1
        img1 = np.zeros((3, 3, 3))
        img1[1, 1, 1] = 1
        img2 = np.zeros((3, 3, 3))
        img2[0, 1, 1] = 1
        img2[2, 2, 1] = 1
        iterable = [img1, img2]
        template_ratio = 0
        scroll_threshold = 0
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertTrue(np.array_equal(gen_img, img0))

        # 2D image, scroll 2 pixels
        img0 = np.zeros((8, 3))
        img0[2, 1] = 1
        img0[6, 1] = 0.1
        img0[7, 1] = 0.2
        img1 = np.zeros((6, 3))
        img1[2, 1] = 1
        img2 = np.zeros((6, 3))
        img2[0, 1] = 1
        img2[4, 1] = 0.1
        img2[5, 1] = 0.2
        iterable = [img1, img2]
        template_ratio = 0
        scroll_threshold = 0
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertTrue(np.array_equal(gen_img, img0))

        # 3D image, scroll 2 pixels
        img0 = np.zeros((8, 3, 3))
        img0[2, 1, 1] = 1
        img0[6, 1, 1] = 0.1
        img0[7, 1, 1] = 0.2
        img1 = np.zeros((6, 3, 3))
        img1[2, 1, 1] = 1
        img2 = np.zeros((6, 3, 3))
        img2[0, 1, 1] = 1
        img2[4, 1, 1] = 0.1
        img2[5, 1, 1] = 0.2
        iterable = [img1, img2]
        template_ratio = 0
        scroll_threshold = 0
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertTrue(np.array_equal(gen_img, img0))

        # 2D images x 3
        img0 = np.zeros((5, 3))
        img0[1, 0] = 1
        img0[3, 0] = 0.1
        img0[4, 0] = 0.2
        img1 = np.zeros((3, 3))
        img1[1, 0] = 1
        img2 = np.zeros((3, 3))
        img2[0, 0] = 1
        img2[1, 1] = 1
        img2[2, 0] = 0.1
        img3 = np.zeros((3, 3))
        img3[0, 1] = 1
        img3[2, 0] = 0.2
        iterable = [img1, img2, img3]
        template_ratio = 0
        scroll_threshold = 0
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertTrue(np.array_equal(gen_img, img0))

        # 3D images x 3
        img0 = np.zeros((5, 3, 3))
        img0[1, 0, 1] = 1
        img0[3, 0, 1] = 0.1
        img0[4, 0, 1] = 0.2
        img1 = np.zeros((3, 3, 3))
        img1[1, 0, 1] = 1
        img2 = np.zeros((3, 3, 3))
        img2[0, 0, 1] = 1
        img2[1, 1, 1] = 1
        img2[2, 0, 1] = 0.1
        img3 = np.zeros((3, 3, 3))
        img3[0, 1, 1] = 1
        img3[2, 0, 1] = 0.2
        iterable = [img1, img2, img3]
        template_ratio = 0
        scroll_threshold = 0
        gen_img = sw_luadocs.capture.stitch_screenshot(
            iterable, template_ratio=template_ratio, scroll_threshold=scroll_threshold
        )
        self.assertTrue(np.array_equal(gen_img, img0))
