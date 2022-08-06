import numpy as np
import sw_luadocs.capture
import tkinter
import unittest
import win32api


class TestActivateWindow(unittest.TestCase):
    def test_invalid_hwnd(self):
        result = sw_luadocs.capture.activate_window(0)
        self.assertFalse(result)

    def test_already_focused(self):
        for input_state, expected_state in [
            ("normal", "normal"),
            ("iconic", "normal"),
            ("zoomed", "zoomed"),
        ]:
            with self.subTest(state=input_state):
                tk = tkinter.Tk()
                try:
                    tk.wm_state(input_state)
                    tk.update()
                    tk.focus_force()
                    tk.update()
                    input_hwnd = int(tk.wm_frame(), 16)
                    actual_result = sw_luadocs.capture.activate_window(input_hwnd)
                    tk.update()
                    actual_foreground = tk.focus_get() == tk
                    actual_state = tk.wm_state()
                finally:
                    tk.destroy()
                self.assertTrue(actual_result)
                self.assertTrue(actual_foreground)
                self.assertEqual(actual_state, expected_state)

    def test_main(self):
        for input_state, expected_state in [
            ("normal", "normal"),
            ("iconic", "normal"),
            ("zoomed", "zoomed"),
        ]:
            with self.subTest(state=input_state):
                tk = tkinter.Tk()
                try:
                    tk.wm_state(input_state)
                    tk_top = tkinter.Toplevel(tk)
                    tk.update()
                    tk_top.focus_force()
                    tk.update()
                    input_hwnd = int(tk.wm_frame(), 16)
                    actual_result = sw_luadocs.capture.activate_window(input_hwnd)
                    tk.update()
                    actual_foreground = tk.focus_get() == tk
                    actual_state = tk.wm_state()
                finally:
                    tk.destroy()
                self.assertTrue(actual_result)
                self.assertTrue(actual_foreground)
                self.assertEqual(actual_state, expected_state)


class TestIsFullscreen(unittest.TestCase):
    def test_invalid_hwnd(self):
        fullscreen = sw_luadocs.capture.is_fullscreen(0)
        self.assertEqual(fullscreen, False)

    def test_main(self):
        scr_w = win32api.GetSystemMetrics(0)
        scr_h = win32api.GetSystemMetrics(1)

        for input_foreground, input_topmost, input_geometry, expected_fullscreen in [
            (True, True, f"{scr_w}x{scr_h}+0+0", True),
            (False, True, f"{scr_w}x{scr_h}+0+0", False),
            (True, False, f"{scr_w}x{scr_h}+0+0", False),
            (True, True, f"{scr_w}x{scr_h}+1+0", False),
            (True, True, f"{scr_w}x{scr_h}+0+1", False),
            (True, True, f"{scr_w-1}x{scr_h}+0+0", False),
            (True, True, f"{scr_w}x{scr_h-1}+0+0", False),
        ]:
            with self.subTest(
                foreground=input_foreground,
                topmost=input_topmost,
                geometry=input_geometry,
            ):
                tk = tkinter.Tk()
                try:
                    tk.wm_overrideredirect(True)
                    if input_foreground:
                        tk.focus_force()
                    else:
                        tk_top = tkinter.Toplevel(tk)
                        tk_top.focus_force()
                    tk.wm_attributes("-topmost", input_topmost)
                    tk.wm_geometry(input_geometry)
                    tk.update()
                    input_hwnd = int(tk.wm_frame(), 16)
                    actual_fullscreen = sw_luadocs.capture.is_fullscreen(input_hwnd)
                finally:
                    tk.destroy()
                self.assertEqual(actual_fullscreen, expected_fullscreen)


class TestSendMouseWheel(unittest.TestCase):
    def test_invalid_hwnd(self):
        with self.assertRaises(RuntimeError):
            sw_luadocs.capture.send_mousewheel(0, 0, 0, 0)

    def test_invalid_value(self):
        scr_w = win32api.GetSystemMetrics(0)
        scr_h = win32api.GetSystemMetrics(1)

        for x, y in [(-1, 0), (0, -1), (scr_w, 0), (0, scr_h)]:
            with self.subTest(x=x, y=y):
                with self.assertRaises(ValueError):
                    sw_luadocs.capture.send_mousewheel(0, x, y, 0)

    def test_main(self):
        scr_w = win32api.GetSystemMetrics(0)
        scr_h = win32api.GetSystemMetrics(1)

        for input_x, input_y, input_delta, input_prev_x, input_prev_y in [
            (1, 2, 120, 3, 4),
            (scr_w - 1, scr_h - 2, -240, scr_w - 3, scr_h - 4),
        ]:
            with self.subTest(
                x=input_x,
                y=input_y,
                delta=input_delta,
                prev_x=input_prev_x,
                prev_y=input_prev_y,
            ):
                actual_event = None

                tk = tkinter.Tk()
                try:
                    tk.wm_overrideredirect(True)
                    tk.wm_attributes("-topmost", True)
                    tk.wm_geometry(f"{scr_w}x{scr_h}+0+0")
                    tk.update()
                    tk.focus_force()
                    tk.update()

                    input_hwnd = int(tk.wm_frame(), 16)
                    input_cur_x, input_cur_y = win32api.GetCursorPos()
                    try:
                        win32api.SetCursorPos((input_prev_x, input_prev_y))
                        sw_luadocs.capture.send_mousewheel(
                            input_hwnd, input_x, input_y, input_delta
                        )
                        actual_prev_x, actual_prev_y = win32api.GetCursorPos()
                    finally:
                        win32api.SetCursorPos((input_cur_x, input_cur_y))

                    def callback(event):
                        nonlocal actual_event
                        actual_event = event
                        tk.quit()

                    tk.after(1000, lambda: tk.quit())
                    tk.bind("<MouseWheel>", callback)
                    tk.mainloop()
                finally:
                    tk.destroy()

                self.assertIsNotNone(actual_event)
                self.assertEqual(actual_event.x, input_x)
                self.assertEqual(actual_event.y, input_y)
                self.assertEqual(actual_event.delta, input_delta)
                self.assertEqual(actual_prev_x, input_prev_x)
                self.assertEqual(actual_prev_y, input_prev_y)


class TestCaptureScreenshot(unittest.TestCase):
    def test_invalid_value(self):
        scr_w = win32api.GetSystemMetrics(0)
        scr_h = win32api.GetSystemMetrics(1)

        for capture_area in [
            (-1, 0, 1, 1),
            (scr_w, 0, 1, 1),
            (0, -1, 1, 1),
            (0, scr_h, 1, 1),
            (0, 0, 0, 1),
            (0, 0, scr_w + 1, 1),
            (1, 0, scr_w, 1),
            (0, 0, 1, 0),
            (0, 0, 1, scr_h + 1),
            (0, 1, 1, scr_h),
        ]:
            with self.subTest(capture_area=capture_area):
                with self.assertRaises(ValueError):
                    sw_luadocs.capture.capture_screenshot(capture_area=capture_area)

    def test_main(self):
        scr_w = win32api.GetSystemMetrics(0)
        scr_h = win32api.GetSystemMetrics(1)

        for input_capture_area, expected_img_w, expected_img_h in [
            (None, scr_w, scr_h),
            ((0, 0, scr_w, scr_h), scr_w, scr_h),
            ((0, 0, scr_w - 1, scr_h), scr_w - 1, scr_h),
            ((0, 0, scr_w, scr_h - 1), scr_w, scr_h - 1),
        ]:
            with self.subTest(capture_area=input_capture_area):
                actual_capture_img = sw_luadocs.capture.capture_screenshot(
                    capture_area=input_capture_area
                )
                actual_img_h, actual_img_w, _ = actual_capture_img.shape
                self.assertEqual(actual_img_w, expected_img_w)
                self.assertEqual(actual_img_h, expected_img_h)


class TestCaptureGame(unittest.TestCase):
    def test_invalid_hwnd(self):
        with self.assertRaises(RuntimeError):
            sw_luadocs.capture.capture_game(0)

    def test_main(self):
        scr_w = win32api.GetSystemMetrics(0)
        scr_h = win32api.GetSystemMetrics(1)

        tk = tkinter.Tk()
        try:
            tk.wm_overrideredirect(True)
            tk.wm_attributes("-topmost", True)
            tk.wm_geometry(f"{scr_w}x{scr_h}+0+0")
            tk.update()
            tk.focus_force()
            tk.update()
            hwnd = int(tk.wm_frame(), 16)
            capture_img = sw_luadocs.capture.capture_game(
                hwnd, capture_area=(0, 0, 1, 2)
            )
        finally:
            tk.destroy()

        img_h, img_w, _ = capture_img.shape
        self.assertEqual(img_w, 1)
        self.assertEqual(img_h, 2)


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
