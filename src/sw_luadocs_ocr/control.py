import ahk
import ctypes
import ctypes.wintypes
import d3dshot
import re
import time


def ahkid_to_hwnd(ahk_id):
    ahk_id = str(ahk_id)
    if re.match(r"(?i)^0[xX][0-9A-Fa-f]+$", ahk_id) is None:
        raise ValueError("Not an ahk_id")
    return int(ahk_id, base=16)


def get_client_rect(hwnd):
    def errcheck(result, func, args):
        if result == 0:
            raise ctypes.WinError()
        return result

    GetClientRect = ctypes.windll.user32.GetClientRect
    GetClientRect.argtypes = ctypes.wintypes.HWND, ctypes.POINTER(ctypes.wintypes.RECT)
    GetClientRect.restype = ctypes.wintypes.BOOL
    GetClientRect.errcheck = errcheck
    rect = ctypes.wintypes.RECT()
    GetClientRect(hwnd, ctypes.byref(rect))
    return rect.left, rect.top, rect.right, rect.bottom


def client_to_screen(hwnd):
    def errcheck(result, func, args):
        if result == 0:
            raise RuntimeError
        return result

    ClientToScreen = ctypes.windll.user32.ClientToScreen
    ClientToScreen.argtypes = ctypes.wintypes.HWND, ctypes.POINTER(
        ctypes.wintypes.POINT
    )
    ClientToScreen.restype = ctypes.wintypes.BOOL
    ClientToScreen.errcheck = errcheck
    point = ctypes.wintypes.POINT()
    ClientToScreen(hwnd, ctypes.byref(point))
    return point.x, point.y


def get_system_metrics(idx):
    GetSystemMetrics = ctypes.windll.user32.GetSystemMetrics
    GetSystemMetrics.argtypes = (ctypes.c_int,)
    GetSystemMetrics.restype = ctypes.c_int
    return GetSystemMetrics(idx)


def screenshot(capture_output="pil", region=None):
    # Do not run this function concurrently with itself or
    # with any other function that uses the Desktop Duplication API.

    # We create a D3DShot instance for each operation,
    # to avoid D3DShot getting stuck when D3DCtx is changed.
    # Note:
    #   This workaround does not work with d3dshot>=0.15,
    #   because the D3DShot instance is not released.
    # Related issues:
    #   - https://github.com/SerpentAI/D3DShot/issues/38
    #   - https://github.com/SerpentAI/D3DShot/issues/30
    d = d3dshot.create(capture_output=capture_output)
    return d.screenshot(region=region)


class StormworksController:
    def __init__(
        self,
        *,
        ahk_executable_path="",
        title="Stormworks",
        text="",
        exclude_title="",
        exclude_text=""
    ):
        self._ahk = ahk.AHK(executable_path=ahk_executable_path)
        self._win = self._ahk.win_get(
            title=title,
            text=text,
            exclude_title=exclude_title,
            exclude_text=exclude_text,
        )
        if self._win.id == "":
            raise RuntimeError("Stormworks window is missing")

        self.activate_sleep_secs = 5
        self.scroll_sleep_secs = 5
        self.minimize_sleep_secs = 5

    def hwnd(self):
        return ahkid_to_hwnd(self._win.id)

    def client_pos(self):
        hwnd = self.hwnd()
        _, _, width, height = get_client_rect(hwnd)
        x, y = client_to_screen(hwnd)
        return x, y, width, height

    def is_fullscreen(self):
        if not self._win.exists or not self._win.always_on_top:
            return False
        scr_w = get_system_metrics(0)
        scr_h = get_system_metrics(1)
        win_x, win_y, win_w, win_h = self.client_pos()
        return win_x == 0 and win_y == 0 and win_w == scr_w and win_h == scr_h

    def check_exists(self):
        if not self._win.exists:
            raise RuntimeError("Stormworks window is missing")

    def check_fullscreen(self):
        if not self.is_fullscreen():
            raise RuntimeError("Stormworks is not full screen")

    def activate(self, sleep=True):
        self.check_exists()
        if not self._win.active:
            self._win.activate()
            if sleep:
                time.sleep(self.activate_sleep_secs)

    def minimize(self, sleep=True):
        self.check_exists()
        if not self._win.minimized:
            self._win.minimize()
            if sleep:
                time.sleep(self.minimize_sleep_secs)

    def mouse_wheel(self, direction, *, x=None, y=None, n=None, sleep=True):
        self.check_fullscreen()
        self._ahk.mouse_wheel(
            direction,
            x=x,
            y=y,
            n=n,
            relative=False,
            blocking=True,
            mode="Screen",
        )
        if sleep:
            time.sleep(self.scroll_sleep_secs)

    def screenshot(self, *, capture_output="pil", region=None):
        self.check_fullscreen()
        return screenshot(capture_output=capture_output, region=region)

    def scroll_and_screenshot(
        self,
        *,
        scroll_direction="down",
        scroll_x=None,
        scroll_y=None,
        scroll_n=None,
        capture_output="pil",
        capture_region=None
    ):
        while True:
            yield self.screenshot(capture_output=capture_output, region=capture_region)
            self.mouse_wheel(scroll_direction, x=scroll_x, y=scroll_y, n=scroll_n)
