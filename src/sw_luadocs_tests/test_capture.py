import numpy as np
import sw_luadocs.capture
import unittest


class TestAHKIDToHWND(unittest.TestCase):
    def test_validate_convert(self):
        with self.assertRaises(ValueError):
            sw_luadocs.capture.ahkid_to_hwnd(0)

    def test_validate_re_pass(self):
        for ahk_id in ["0x3e0448", "0X3E0448"]:
            with self.subTest(ahk_id=ahk_id):
                hwnd = sw_luadocs.capture.ahkid_to_hwnd(ahk_id)
                self.assertEqual(hwnd, 4064328)

    def test_validate_re_error(self):
        for ahk_id in ["-0x3e0448", "3e0448", "0x3g0448", "0x3e0448 "]:
            with self.subTest(ahk_id=ahk_id):
                with self.assertRaises(ValueError):
                    sw_luadocs.capture.ahkid_to_hwnd(ahk_id)

    def test_convert(self):
        hwnd = sw_luadocs.capture.ahkid_to_hwnd("0x3e0448")
        self.assertEqual(hwnd, 4064328)


class TestImageProcessing(unittest.TestCase):
    def test_calc_scroll_amount(self):
        # type conversion
        old_img = [[0]]
        new_img = [[0]]
        template_ratio = "0"
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

        # shape mismatch
        old_img = np.zeros((1, 1))
        new_img = np.zeros((1, 2))
        template_ratio = 0
        with self.assertRaisesRegex(ValueError, r"^Image shape does not match$"):
            sw_luadocs.capture.calc_scroll_amount(
                old_img, new_img, template_ratio=template_ratio
            )

        # ndim too small
        old_img = np.zeros(1)
        new_img = np.zeros(1)
        template_ratio = 0
        with self.assertRaisesRegex(ValueError, r"^The given data is not an image$"):
            sw_luadocs.capture.calc_scroll_amount(
                old_img, new_img, template_ratio=template_ratio
            )

        # ndim too large
        old_img = np.zeros((1, 1, 1, 1))
        new_img = np.zeros((1, 1, 1, 1))
        template_ratio = 0
        with self.assertRaisesRegex(ValueError, r"^The given data is not an image$"):
            sw_luadocs.capture.calc_scroll_amount(
                old_img, new_img, template_ratio=template_ratio
            )

        # empty image
        old_img = np.zeros((0, 0))
        new_img = np.zeros((0, 0))
        template_ratio = 0
        with self.assertRaisesRegex(ValueError, r"^The image is empty$"):
            sw_luadocs.capture.calc_scroll_amount(
                old_img, new_img, template_ratio=template_ratio
            )

        # template_ratio too small
        old_img = np.zeros((1, 1))
        new_img = np.zeros((1, 1))
        template_ratio = -1
        with self.assertRaisesRegex(
            ValueError, r"^template_ratio is not within the range 0~1$"
        ):
            sw_luadocs.capture.calc_scroll_amount(
                old_img, new_img, template_ratio=template_ratio
            )

        # template_ratio too large
        old_img = np.zeros((1, 1))
        new_img = np.zeros((1, 1))
        template_ratio = 2
        with self.assertRaisesRegex(
            ValueError, r"^template_ratio is not within the range 0~1$"
        ):
            sw_luadocs.capture.calc_scroll_amount(
                old_img, new_img, template_ratio=template_ratio
            )

        # 2D smallest image, smallest template_ratio
        old_img = np.zeros((1, 1))
        new_img = np.zeros((1, 1))
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

        # 2D smallest image, largest template_ratio
        old_img = np.zeros((1, 1))
        new_img = np.zeros((1, 1))
        template_ratio = 1
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

        # 3D smallest image, smallest template_ratio
        old_img = np.zeros((1, 1, 3))
        new_img = np.zeros((1, 1, 3))
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

        # 3D smallest image, largest template_ratio
        old_img = np.zeros((1, 1, 3))
        new_img = np.zeros((1, 1, 3))
        template_ratio = 1
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

        # 2D 3x3 image, smallest template_ratio, scroll down
        old_img = np.zeros((3, 3))
        old_img[1, 1] = 1
        new_img = np.zeros((3, 3))
        new_img[2, 1] = 1
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 1)

        # 2D 3x3 image, smallest template_ratio, scroll up
        old_img = np.zeros((3, 3))
        old_img[1, 1] = 1
        new_img = np.zeros((3, 3))
        new_img[0, 1] = 1
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, -1)

        # 3D 3x3 image, smallest template_ratio, scroll down
        old_img = np.zeros((3, 3, 3))
        old_img[1, 1, 1] = 1
        new_img = np.zeros((3, 3, 3))
        new_img[2, 1, 1] = 1
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 1)

        # 3D 3x3 image, smallest template_ratio, scroll up
        old_img = np.zeros((3, 3, 3))
        old_img[1, 1, 1] = 1
        new_img = np.zeros((3, 3, 3))
        new_img[0, 1, 1] = 1
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, -1)

        # 3D 3x3 image, largest template_ratio, scroll down
        old_img = np.zeros((3, 3, 3))
        old_img[1, 1, 1] = 1
        new_img = np.zeros((3, 3, 3))
        new_img[2, 1, 1] = 1
        template_ratio = 1
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

        # 3D 3x3 image, largest template_ratio, scroll up
        old_img = np.zeros((3, 3, 3))
        old_img[1, 1, 1] = 1
        new_img = np.zeros((3, 3, 3))
        new_img[0, 1, 1] = 1
        template_ratio = 1
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

        # 2D 9x9 image, medium template_ratio, scroll down
        old_img = np.zeros((9, 9))
        old_img[0, 3] = 1
        old_img[1, 4] = 1
        old_img[2, 5] = 1
        old_img[3, 5] = 1
        old_img[4, 4] = 1
        old_img[5, 3] = 1
        old_img[6, 3] = 1
        old_img[7, 4] = 1
        old_img[8, 5] = 1
        new_img = np.zeros((9, 9))
        new_img[0, 3] = 1
        new_img[1, 4] = 1
        new_img[2, 5] = 1
        new_img[3, 3] = 1
        new_img[4, 4] = 1
        new_img[5, 5] = 1
        new_img[6, 5] = 1
        new_img[7, 4] = 1
        new_img[8, 3] = 1
        template_ratio = 1 / 3
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 3)

        # 2D 9x9 image, smallest template_ratio, scroll up
        old_img = np.zeros((9, 9))
        old_img[4, 4] = 1
        new_img = np.zeros((9, 9))
        new_img[8, 4] = 1
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 4)

        # 2D 9x9 image, smallest template_ratio, scroll down
        old_img = np.zeros((9, 9))
        old_img[4, 4] = 1
        new_img = np.zeros((9, 9))
        new_img[0, 4] = 1
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, -4)

        # 3D 9x9 image, smallest template_ratio, scroll up
        old_img = np.zeros((9, 9, 3))
        old_img[4, 4, 1] = 1
        new_img = np.zeros((9, 9, 3))
        new_img[8, 4, 1] = 1
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 4)

        # 3D 9x9 image, smallest template_ratio, scroll down
        old_img = np.zeros((9, 9, 3))
        old_img[4, 4, 1] = 1
        new_img = np.zeros((9, 9, 3))
        new_img[0, 4, 1] = 1
        template_ratio = 0
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, -4)

        # 2D 9x9 image, medium template_ratio, scroll up
        old_img = np.zeros((9, 9))
        old_img[0, 3] = 1
        old_img[1, 4] = 1
        old_img[2, 5] = 1
        old_img[3, 5] = 1
        old_img[4, 4] = 1
        old_img[5, 3] = 1
        old_img[6, 3] = 1
        old_img[7, 4] = 1
        old_img[8, 5] = 1
        new_img = np.zeros((9, 9))
        new_img[0, 5] = 1
        new_img[1, 4] = 1
        new_img[2, 3] = 1
        new_img[3, 3] = 1
        new_img[4, 4] = 1
        new_img[5, 5] = 1
        new_img[6, 3] = 1
        new_img[7, 4] = 1
        new_img[8, 5] = 1
        template_ratio = 1 / 3
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, -3)

        # 3D 9x9 image, medium template_ratio, scroll down
        old_img = np.zeros((9, 9, 3))
        old_img[0, 3, 1] = 1
        old_img[1, 4, 1] = 1
        old_img[2, 5, 1] = 1
        old_img[3, 5, 1] = 1
        old_img[4, 4, 1] = 1
        old_img[5, 3, 1] = 1
        old_img[6, 3, 1] = 1
        old_img[7, 4, 1] = 1
        old_img[8, 5, 1] = 1
        new_img = np.zeros((9, 9, 3))
        new_img[0, 3, 1] = 1
        new_img[1, 4, 1] = 1
        new_img[2, 5, 1] = 1
        new_img[3, 3, 1] = 1
        new_img[4, 4, 1] = 1
        new_img[5, 5, 1] = 1
        new_img[6, 5, 1] = 1
        new_img[7, 4, 1] = 1
        new_img[8, 3, 1] = 1
        template_ratio = 1 / 3
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 3)

        # 3D 9x9 image, medium template_ratio, scroll up
        old_img = np.zeros((9, 9, 3))
        old_img[0, 3, 1] = 1
        old_img[1, 4, 1] = 1
        old_img[2, 5, 1] = 1
        old_img[3, 5, 1] = 1
        old_img[4, 4, 1] = 1
        old_img[5, 3, 1] = 1
        old_img[6, 3, 1] = 1
        old_img[7, 4, 1] = 1
        old_img[8, 5, 1] = 1
        new_img = np.zeros((9, 9, 3))
        new_img[0, 5, 1] = 1
        new_img[1, 4, 1] = 1
        new_img[2, 3, 1] = 1
        new_img[3, 3, 1] = 1
        new_img[4, 4, 1] = 1
        new_img[5, 5, 1] = 1
        new_img[6, 3, 1] = 1
        new_img[7, 4, 1] = 1
        new_img[8, 5, 1] = 1
        template_ratio = 1 / 3
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, -3)

        # 3D 9x9 image, largest template_ratio, scroll down
        old_img = np.zeros((9, 9, 3))
        old_img[0, 3, 1] = 1
        old_img[1, 4, 1] = 1
        old_img[2, 5, 1] = 1
        old_img[3, 5, 1] = 1
        old_img[4, 4, 1] = 1
        old_img[5, 3, 1] = 1
        old_img[6, 3, 1] = 1
        old_img[7, 4, 1] = 1
        old_img[8, 5, 1] = 1
        new_img = np.zeros((9, 9, 3))
        new_img[0, 3, 1] = 1
        new_img[1, 4, 1] = 1
        new_img[2, 5, 1] = 1
        new_img[3, 3, 1] = 1
        new_img[4, 4, 1] = 1
        new_img[5, 5, 1] = 1
        new_img[6, 5, 1] = 1
        new_img[7, 4, 1] = 1
        new_img[8, 3, 1] = 1
        template_ratio = 1
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

        # 3D 9x9 image, largest template_ratio, scroll up
        old_img = np.zeros((9, 9, 3))
        old_img[0, 3, 1] = 1
        old_img[1, 4, 1] = 1
        old_img[2, 5, 1] = 1
        old_img[3, 5, 1] = 1
        old_img[4, 4, 1] = 1
        old_img[5, 3, 1] = 1
        old_img[6, 3, 1] = 1
        old_img[7, 4, 1] = 1
        old_img[8, 5, 1] = 1
        new_img = np.zeros((9, 9, 3))
        new_img[0, 5, 1] = 1
        new_img[1, 4, 1] = 1
        new_img[2, 3, 1] = 1
        new_img[3, 3, 1] = 1
        new_img[4, 4, 1] = 1
        new_img[5, 5, 1] = 1
        new_img[6, 3, 1] = 1
        new_img[7, 4, 1] = 1
        new_img[8, 5, 1] = 1
        template_ratio = 1
        scroll_amount = sw_luadocs.capture.calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        self.assertEqual(scroll_amount, 0)

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
