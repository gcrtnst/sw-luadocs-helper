import ctypes
import sw_luadocs.win32
import unittest


class TestMOUSEINPUTInit(unittest.TestCase):
    def test_main(self):
        for (
            input_args,
            input_kwargs,
            expected_dx,
            expected_dy,
            expected_mouseData,
            expected_dwFlags,
            expected_time,
            expected_dwExtraInfo,
        ) in [
            ([], {}, 0, 0, 0, 0, 0, 0),
            ([1, 2, 3, 4, 5, 6], {}, 1, 2, 3, 4, 5, 6),
            (
                [],
                {
                    "dx": 1,
                    "dy": 2,
                    "mouseData": 3,
                    "dwFlags": 4,
                    "time": 5,
                    "dwExtraInfo": 6,
                },
                1,
                2,
                3,
                4,
                5,
                6,
            ),
        ]:
            with self.subTest(args=input_args, kwargs=input_kwargs):
                mi = sw_luadocs.win32.MOUSEINPUT(*input_args, **input_kwargs)
                self.assertEqual(mi._c.type, sw_luadocs.win32.INPUT_MOUSE)
                self.assertEqual(mi._c.mi.dx, expected_dx)
                self.assertEqual(mi._c.mi.dy, expected_dy)
                self.assertEqual(mi._c.mi.mouseData, expected_mouseData)
                self.assertEqual(mi._c.mi.dwFlags, expected_dwFlags)
                self.assertEqual(mi._c.mi.time, expected_time)
                self.assertEqual(mi._c.mi.dwExtraInfo, expected_dwExtraInfo)


class TestMOUSEINPUTGetAttr(unittest.TestCase):
    def test_invalid_attr(self):
        mi = sw_luadocs.win32.MOUSEINPUT()
        with self.assertRaises(AttributeError):
            mi.nonexistent

    def test_main(self):
        mi = sw_luadocs.win32.MOUSEINPUT()
        mi._c.mi.dx = 1
        mi._c.mi.dy = 2
        mi._c.mi.mouseData = 3
        mi._c.mi.dwFlags = 4
        mi._c.mi.time = 5
        mi._c.mi.dwExtraInfo = 6
        self.assertEqual(mi.dx, 1)
        self.assertEqual(mi.dy, 2)
        self.assertEqual(mi.mouseData, 3)
        self.assertEqual(mi.dwFlags, 4)
        self.assertEqual(mi.time, 5)
        self.assertEqual(mi.dwExtraInfo, 6)


class TestMOUSEINPUTSetAttr(unittest.TestCase):
    def test_main(self):
        mi = sw_luadocs.win32.MOUSEINPUT()
        mi.dx = 1
        mi.dy = 2
        mi.mouseData = 3
        mi.dwFlags = 4
        mi.time = 5
        mi.dwExtraInfo = 6
        self.assertEqual(mi._c.mi.dx, 1)
        self.assertEqual(mi._c.mi.dy, 2)
        self.assertEqual(mi._c.mi.mouseData, 3)
        self.assertEqual(mi._c.mi.dwFlags, 4)
        self.assertEqual(mi._c.mi.time, 5)
        self.assertEqual(mi._c.mi.dwExtraInfo, 6)

    def test_nonexistent(self):
        mi = sw_luadocs.win32.MOUSEINPUT()
        mi.nonexistent = 1
        self.assertEqual(mi.nonexistent, 1)


class TestMOUSEINPUTDir(unittest.TestCase):
    def test_main(self):
        mi = sw_luadocs.win32.MOUSEINPUT()
        self.assertTrue(
            {
                "dx",
                "dy",
                "mouseData",
                "dwFlags",
                "time",
                "dwExtraInfo",
                "__dir__",
            }.issubset(dir(mi))
        )


class TestKEYBDINPUTInit(unittest.TestCase):
    def test_main(self):
        for (
            input_args,
            input_kwargs,
            expected_wVk,
            expected_wScan,
            expected_dwFlags,
            expected_time,
            expected_dwExtraInfo,
        ) in [
            ([], {}, 0, 0, 0, 0, 0),
            ([1, 2, 3, 4, 5], {}, 1, 2, 3, 4, 5),
            (
                [],
                {"wVk": 1, "wScan": 2, "dwFlags": 3, "time": 4, "dwExtraInfo": 5},
                1,
                2,
                3,
                4,
                5,
            ),
        ]:
            with self.subTest(args=input_args, kwargs=input_kwargs):
                ki = sw_luadocs.win32.KEYBDINPUT(*input_args, **input_kwargs)
                self.assertEqual(ki._c.type, sw_luadocs.win32.INPUT_KEYBOARD)
                self.assertEqual(ki._c.ki.wVk, expected_wVk)
                self.assertEqual(ki._c.ki.wScan, expected_wScan)
                self.assertEqual(ki._c.ki.dwFlags, expected_dwFlags)
                self.assertEqual(ki._c.ki.time, expected_time)
                self.assertEqual(ki._c.ki.dwExtraInfo, expected_dwExtraInfo)


class TestKEYBDINPUTGetAttr(unittest.TestCase):
    def test_invalid_attr(self):
        ki = sw_luadocs.win32.KEYBDINPUT()
        with self.assertRaises(AttributeError):
            ki.nonexistent

    def test_main(self):
        ki = sw_luadocs.win32.KEYBDINPUT()
        ki._c.ki.wVk = 1
        ki._c.ki.wScan = 2
        ki._c.ki.dwFlags = 3
        ki._c.ki.time = 4
        ki._c.ki.dwExtraInfo = 5
        self.assertEqual(ki.wVk, 1)
        self.assertEqual(ki.wScan, 2)
        self.assertEqual(ki.dwFlags, 3)
        self.assertEqual(ki.time, 4)
        self.assertEqual(ki.dwExtraInfo, 5)


class TestKEYBDINPUTSetAttr(unittest.TestCase):
    def test_main(self):
        ki = sw_luadocs.win32.KEYBDINPUT()
        ki.wVk = 1
        ki.wScan = 2
        ki.dwFlags = 3
        ki.time = 4
        ki.dwExtraInfo = 5
        self.assertEqual(ki._c.ki.wVk, 1)
        self.assertEqual(ki._c.ki.wScan, 2)
        self.assertEqual(ki._c.ki.dwFlags, 3)
        self.assertEqual(ki._c.ki.time, 4)
        self.assertEqual(ki._c.ki.dwExtraInfo, 5)

    def test_nonexistent(self):
        ki = sw_luadocs.win32.KEYBDINPUT()
        ki.nonexistent = 1
        self.assertEqual(ki.nonexistent, 1)


class TestKEYBDINPUTDir(unittest.TestCase):
    def test_main(self):
        ki = sw_luadocs.win32.KEYBDINPUT()
        self.assertTrue(
            {
                "wVk",
                "wScan",
                "dwFlags",
                "time",
                "dwExtraInfo",
                "__dir__",
            }.issubset(dir(ki))
        )


class TestHARDWAREINPUTInit(unittest.TestCase):
    def test_main(self):
        for (
            input_args,
            input_kwargs,
            expected_uMsg,
            expected_wParamL,
            expected_wParamH,
        ) in [
            ([], {}, 0, 0, 0),
            ([1, 2, 3], {}, 1, 2, 3),
            ([], {"uMsg": 1, "wParamL": 2, "wParamH": 3}, 1, 2, 3),
        ]:
            with self.subTest(args=input_args, kwargs=input_kwargs):
                hi = sw_luadocs.win32.HARDWAREINPUT(*input_args, **input_kwargs)
                self.assertEqual(hi._c.type, sw_luadocs.win32.INPUT_HARDWARE)
                self.assertEqual(hi._c.hi.uMsg, expected_uMsg)
                self.assertEqual(hi._c.hi.wParamL, expected_wParamL)
                self.assertEqual(hi._c.hi.wParamH, expected_wParamH)


class TestHARDWAREINPUTGetAttr(unittest.TestCase):
    def test_invalid_attr(self):
        hi = sw_luadocs.win32.HARDWAREINPUT()
        with self.assertRaises(AttributeError):
            hi.nonexistent

    def test_main(self):
        hi = sw_luadocs.win32.HARDWAREINPUT()
        hi._c.hi.uMsg = 1
        hi._c.hi.wParamL = 2
        hi._c.hi.wParamH = 3
        self.assertEqual(hi.uMsg, 1)
        self.assertEqual(hi.wParamL, 2)
        self.assertEqual(hi.wParamH, 3)


class TestHARDWAREINPUTSetAttr(unittest.TestCase):
    def test_main(self):
        hi = sw_luadocs.win32.HARDWAREINPUT()
        hi.uMsg = 1
        hi.wParamL = 2
        hi.wParamH = 3
        self.assertEqual(hi._c.hi.uMsg, 1)
        self.assertEqual(hi._c.hi.wParamL, 2)
        self.assertEqual(hi._c.hi.wParamH, 3)

    def test_nonexistent(self):
        hi = sw_luadocs.win32.HARDWAREINPUT()
        hi.nonexistent = 1
        self.assertEqual(hi.nonexistent, 1)


class TestHARDWAREINPUTDir(unittest.TestCase):
    def test_main(self):
        hi = sw_luadocs.win32.HARDWAREINPUT()
        self.assertTrue(
            {
                "uMsg",
                "wParamL",
                "wParamH",
                "__dir__",
            }.issubset(dir(hi))
        )


class TestCreateInputArray(unittest.TestCase):
    def test_invalid_type(self):
        with self.assertRaises(TypeError):
            sw_luadocs.win32._create_input_array(
                [
                    sw_luadocs.win32.MOUSEINPUT(),
                    sw_luadocs.win32.KEYBDINPUT(),
                    sw_luadocs.win32.HARDWAREINPUT(),
                    None,
                ]
            )

    def test_main(self):
        _input_arr = sw_luadocs.win32._create_input_array(
            [
                sw_luadocs.win32.MOUSEINPUT(
                    dx=1, dy=2, mouseData=3, dwFlags=4, time=5, dwExtraInfo=6
                ),
                sw_luadocs.win32.KEYBDINPUT(
                    wVk=7, wScan=8, dwFlags=9, time=10, dwExtraInfo=11
                ),
                sw_luadocs.win32.HARDWAREINPUT(uMsg=12, wParamL=13, wParamH=14),
            ]
        )
        self.assertIsInstance(_input_arr, ctypes.Array)
        self.assertEqual(_input_arr._length_, 3)
        self.assertIs(_input_arr._type_, sw_luadocs.win32._INPUT)
        self.assertEqual(_input_arr[0].type, sw_luadocs.win32.INPUT_MOUSE)
        self.assertEqual(_input_arr[0].mi.dx, 1)
        self.assertEqual(_input_arr[0].mi.dy, 2)
        self.assertEqual(_input_arr[0].mi.mouseData, 3)
        self.assertEqual(_input_arr[0].mi.dwFlags, 4)
        self.assertEqual(_input_arr[0].mi.time, 5)
        self.assertEqual(_input_arr[0].mi.dwExtraInfo, 6)
        self.assertEqual(_input_arr[1].type, sw_luadocs.win32.INPUT_KEYBOARD)
        self.assertEqual(_input_arr[1].ki.wVk, 7)
        self.assertEqual(_input_arr[1].ki.wScan, 8)
        self.assertEqual(_input_arr[1].ki.dwFlags, 9)
        self.assertEqual(_input_arr[1].ki.time, 10)
        self.assertEqual(_input_arr[1].ki.dwExtraInfo, 11)
        self.assertEqual(_input_arr[2].type, sw_luadocs.win32.INPUT_HARDWARE)
        self.assertEqual(_input_arr[2].hi.uMsg, 12)
        self.assertEqual(_input_arr[2].hi.wParamL, 13)
        self.assertEqual(_input_arr[2].hi.wParamH, 14)

    def test_zero(self):
        _input_arr = sw_luadocs.win32._create_input_array([])
        self.assertIsInstance(_input_arr, ctypes.Array)
        self.assertEqual(_input_arr._length_, 0)
        self.assertIs(_input_arr._type_, sw_luadocs.win32._INPUT)
