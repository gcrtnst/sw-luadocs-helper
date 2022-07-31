import numpy as np
import sw_luadocs.capture
import tkinter
import unittest
import win32api


class TestCheckWindowTopmost(unittest.TestCase):
    def test_invalid_hwnd(self):
        topmost = sw_luadocs.capture.check_window_topmost(0)
        self.assertEqual(topmost, False)

    def test_main(self):
        for input_topmost in [False, True]:
            with self.subTest(topmost=input_topmost):
                tk = tkinter.Tk()
                try:
                    tk.wm_attributes("-topmost", input_topmost)
                    tk.update()
                    input_hwnd = int(tk.wm_frame(), 16)
                    actual_topmost = sw_luadocs.capture.check_window_topmost(input_hwnd)
                finally:
                    tk.destroy()
                self.assertEqual(actual_topmost, input_topmost)


class TestCheckWindowFullscreen(unittest.TestCase):
    def test_invalid_hwnd(self):
        fullscreen = sw_luadocs.capture.check_window_fullscreen(0)
        self.assertEqual(fullscreen, False)

    def test_main(self):
        scr_w = win32api.GetSystemMetrics(0)
        scr_h = win32api.GetSystemMetrics(1)

        for input_topmost, input_geometry, expected_fullscreen in [
            (True, f"{scr_w}x{scr_h}+0+0", True),
            (False, f"{scr_w}x{scr_h}+0+0", False),
            (True, f"{scr_w}x{scr_h}+1+0", False),
            (True, f"{scr_w}x{scr_h}+0+1", False),
            (True, f"{scr_w-1}x{scr_h}+0+0", False),
            (True, f"{scr_w}x{scr_h-1}+0+0", False),
        ]:
            with self.subTest(topmost=input_topmost, geometry=input_geometry):
                tk = tkinter.Tk()
                try:
                    tk.wm_overrideredirect(True)
                    tk.wm_attributes("-topmost", input_topmost)
                    tk.wm_geometry(input_geometry)
                    tk.update()
                    input_hwnd = int(tk.wm_frame(), 16)
                    actual_fullscreen = sw_luadocs.capture.check_window_fullscreen(
                        input_hwnd
                    )
                finally:
                    tk.destroy()
                self.assertEqual(actual_fullscreen, expected_fullscreen)


class TestRestoreWindow(unittest.TestCase):
    def test_invalid_hwnd(self):
        with self.assertRaises(RuntimeError):
            sw_luadocs.capture.restore_window(0)

    def test_main(self):
        for input_state in ["normal", "iconic", "zoomed"]:
            with self.subTest(state=input_state):
                tk = tkinter.Tk()
                try:
                    tk.wm_state(input_state)
                    tk.update()
                    input_hwnd = int(tk.wm_frame(), 16)
                    sw_luadocs.capture.restore_window(input_hwnd)
                    tk.update()
                    actual_state = tk.wm_state()
                finally:
                    tk.destroy()
                self.assertEqual(actual_state, "normal")


class TestStormworksControllerInit(unittest.TestCase):
    def test_winget_error(self):
        with self.assertRaises(RuntimeError):
            sw_luadocs.capture.StormworksController(
                ahk_exe="",
                win_title="ahk_id 0x0",
                win_text="",
                win_exclude_title="",
                win_exclude_text="",
            )


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


class TestStitchScreenshot(unittest.TestCase):
    def test_validate_convert_normal(self):
        img = sw_luadocs.capture.stitch_screenshot([], scroll_threshold="0")
        self.assertIsNone(img)

    def test_validate_convert_iterable(self):
        img = sw_luadocs.capture.stitch_screenshot([np.zeros((1, 2), dtype=int)])
        self.assertTrue(np.array_equal(img, np.zeros((1, 2, 3), dtype=np.uint8)))

    def test_validate_value_pass(self):
        img = sw_luadocs.capture.stitch_screenshot([], scroll_threshold=0)
        self.assertIsNone(img)

    def test_validate_value_error(self):
        with self.assertRaises(ValueError):
            sw_luadocs.capture.stitch_screenshot([], scroll_threshold=-1)

    def test_stitch_none(self):
        img = sw_luadocs.capture.stitch_screenshot([])
        self.assertIsNone(img)

    def test_stitch_array(self):
        for input_kwargs, expected_img in [
            (
                {"iterable": [np.full((1, 1, 3), 23, dtype=np.uint8)]},
                np.full((1, 1, 3), 23, dtype=np.uint8),
            ),
            (
                {
                    "iterable": [
                        np.full((1, 1, 3), 23, dtype=np.uint8),
                        np.full((1, 1, 3), 24, dtype=np.uint8),
                    ],
                    "template_ratio": 0,
                    "scroll_threshold": 0,
                },
                np.full((1, 1, 3), 23, dtype=np.uint8),
            ),
            (
                {
                    "iterable": [
                        np.array(
                            [[[0, 0, 0]], [[1, 1, 1]], [[2, 2, 2]]], dtype=np.uint8
                        ),
                        np.array(
                            [[[1, 1, 1]], [[3, 3, 3]], [[4, 4, 4]]], dtype=np.uint8
                        ),
                        np.array(
                            [[[3, 3, 3]], [[5, 5, 5]], [[6, 6, 6]]], dtype=np.uint8
                        ),
                    ],
                    "template_ratio": 0,
                    "scroll_threshold": 0,
                },
                np.array(
                    [[[0, 0, 0]], [[1, 1, 1]], [[2, 2, 2]], [[4, 4, 4]], [[6, 6, 6]]],
                    dtype=np.uint8,
                ),
            ),
            (
                {
                    "iterable": [
                        np.array(
                            [
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[1, 1, 1]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                            ],
                            dtype=np.uint8,
                        ),
                        np.array(
                            [
                                [[1, 1, 1]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                            ],
                            dtype=np.uint8,
                        ),
                    ],
                    "template_ratio": 0,
                    "scroll_threshold": 1,
                },
                np.array(
                    [
                        [[0, 0, 0]],
                        [[0, 0, 0]],
                        [[1, 1, 1]],
                        [[0, 0, 0]],
                        [[0, 0, 0]],
                        [[0, 0, 0]],
                        [[0, 0, 0]],
                    ],
                    dtype=np.uint8,
                ),
            ),
            (
                {
                    "iterable": [
                        np.array(
                            [
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[1, 1, 1]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                            ],
                            dtype=np.uint8,
                        ),
                        np.array(
                            [
                                [[1, 1, 1]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                            ],
                            dtype=np.uint8,
                        ),
                    ],
                    "template_ratio": 1,
                    "scroll_threshold": 1,
                },
                np.array(
                    [
                        [[0, 0, 0]],
                        [[0, 0, 0]],
                        [[1, 1, 1]],
                        [[0, 0, 0]],
                        [[0, 0, 0]],
                    ],
                    dtype=np.uint8,
                ),
            ),
            (
                {
                    "iterable": [
                        np.array(
                            [
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[1, 1, 1]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                            ],
                            dtype=np.uint8,
                        ),
                        np.array(
                            [
                                [[1, 1, 1]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                                [[0, 0, 0]],
                            ],
                            dtype=np.uint8,
                        ),
                    ],
                    "template_ratio": 0,
                    "scroll_threshold": 2,
                },
                np.array(
                    [
                        [[0, 0, 0]],
                        [[0, 0, 0]],
                        [[1, 1, 1]],
                        [[0, 0, 0]],
                        [[0, 0, 0]],
                    ],
                    dtype=np.uint8,
                ),
            ),
            (
                {
                    "iterable": [
                        np.array(
                            [
                                [[0, 1, 2], [3, 4, 5]],
                                [[6, 7, 8], [9, 10, 11]],
                                [[12, 13, 14], [15, 16, 17]],
                            ],
                            dtype=np.uint8,
                        ),
                        np.array(
                            [
                                [[6, 7, 8], [9, 10, 11]],
                                [[12, 13, 14], [15, 16, 17]],
                                [[18, 19, 20], [21, 22, 23]],
                            ],
                            dtype=np.uint8,
                        ),
                    ],
                    "template_ratio": 0,
                    "scroll_threshold": 0,
                },
                np.array(
                    [
                        [[0, 1, 2], [3, 4, 5]],
                        [[6, 7, 8], [9, 10, 11]],
                        [[12, 13, 14], [15, 16, 17]],
                        [[18, 19, 20], [21, 22, 23]],
                    ],
                    dtype=np.uint8,
                ),
            ),
        ]:
            with self.subTest(kwargs=input_kwargs):
                actual_img = sw_luadocs.capture.stitch_screenshot(**input_kwargs)
                self.assertTrue(np.array_equal(actual_img, expected_img))
