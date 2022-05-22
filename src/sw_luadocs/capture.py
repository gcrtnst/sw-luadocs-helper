import ahk
import ctypes
import ctypes.wintypes
import cv2
import d3dshot
import math
import numpy as np
import time

from . import image as dot_image


def get_client_rect(hwnd):
    if not isinstance(hwnd, int):
        raise TypeError

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
    if not isinstance(hwnd, int):
        raise TypeError

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


def get_screen_size():
    scr_w = get_system_metrics(0)
    scr_h = get_system_metrics(1)
    return scr_w, scr_h


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
        exclude_text="",
    ):
        self._ahk = ahk.AHK(executable_path=ahk_executable_path)
        self._win = self._ahk.win_get(
            title=title,
            text=text,
            exclude_title=exclude_title,
            exclude_text=exclude_text,
        )
        if self._win.id == "":
            raise RuntimeError

        self.activate_sleep_secs = 5
        self.scroll_sleep_secs = 5
        self.minimize_sleep_secs = 5

    def hwnd(self):
        return int(self._win.id, base=16)

    def client_pos(self):
        hwnd = self.hwnd()
        _, _, width, height = get_client_rect(hwnd)
        x, y = client_to_screen(hwnd)
        return x, y, width, height

    def is_fullscreen(self):
        if not self._win.exists() or not self._win.always_on_top:
            return False
        scr_w, scr_h = get_screen_size()
        win_x, win_y, win_w, win_h = self.client_pos()
        return win_x == 0 and win_y == 0 and win_w == scr_w and win_h == scr_h

    def check_exists(self):
        if not self._win.exists():
            raise RuntimeError

    def check_fullscreen(self):
        if not self.is_fullscreen():
            raise RuntimeError

    def activate(self, *, sleep=True):
        self.check_exists()
        if not self._win.is_active():
            self._win.activate()
            if sleep:
                time.sleep(self.activate_sleep_secs)

    def minimize(self, *, sleep=True):
        self.check_exists()
        if not self._win.is_minimized():
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
        capture_region=None,
    ):
        while True:
            yield self.screenshot(capture_output=capture_output, region=capture_region)
            self.mouse_wheel(scroll_direction, x=scroll_x, y=scroll_y, n=scroll_n)


def calc_scroll_amount(old_img, new_img, *, template_ratio=0.25):
    old_img = dot_image.convert_image(old_img, dst_mode="RGB")
    new_img = dot_image.convert_image(new_img, dst_mode="RGB")
    template_ratio = float(template_ratio)

    if (
        old_img.size <= 0
        or old_img.shape != new_img.shape
        or not math.isfinite(template_ratio)
        or template_ratio < 0
        or 1 < template_ratio
    ):
        raise ValueError

    img_h, img_w, _ = old_img.shape
    template_h = max(1, int(img_h * template_ratio))
    template_old_y = (img_h - template_h) // 2
    template = old_img[template_old_y : template_old_y + template_h]
    ccoeff = cv2.matchTemplate(new_img, template, cv2.TM_CCOEFF)
    template_new_y = np.reshape(np.argmax(ccoeff, axis=0), 1)[0]
    return template_new_y - template_old_y


def stitch_screenshot(iterable, *, template_ratio=0.25, scroll_threshold=0):
    scroll_threshold = int(scroll_threshold)
    if scroll_threshold < 0:
        raise ValueError

    old_img = None
    gen_img = None
    for new_img in iterable:
        new_img = dot_image.convert_image(new_img, dst_mode="RGB")
        if old_img is None:
            old_img = new_img
            gen_img = new_img
            continue

        scroll_amount = calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        scroll_pixels = -scroll_amount
        if scroll_pixels <= scroll_threshold:
            break

        tmp_img = np.zeros(
            (gen_img.shape[0] + scroll_pixels, gen_img.shape[1], gen_img.shape[2]),
            dtype=gen_img.dtype,
        )
        tmp_img[:-scroll_pixels] = gen_img
        tmp_img[-scroll_pixels:] = new_img[-scroll_pixels:]

        old_img = new_img
        gen_img = tmp_img
    return gen_img


def capture(
    *,
    ahk_exe=None,
    win_title="",
    win_text="",
    win_exclude_title="",
    win_exclude_text="",
    screen_width=1,
    screen_height=1,
    scroll_x=0,
    scroll_y=0,
    scroll_page_n=1,
    scroll_once_n=1,
    scroll_threshold=0,
    capture_region=(0, 0, 0, 0),
    capture_template_ratio=0,
    activate_sleep_secs=0,
    scroll_sleep_secs=0,
):
    if ahk_exe is not None:
        ahk_exe = str(ahk_exe)
    else:
        ahk_exe = ""

    screen_width = int(screen_width)
    screen_height = int(screen_height)
    scroll_x = int(scroll_x)
    scroll_y = int(scroll_y)
    scroll_page_n = int(scroll_page_n)
    scroll_once_n = int(scroll_once_n)
    if screen_width <= 0 or screen_height <= 0:
        raise ValueError(f"invalid screen resolution {screen_width}x{screen_height}")
    if (
        scroll_x < 0
        or screen_width - 1 < scroll_x
        or scroll_y < 0
        or screen_height < scroll_y
    ):
        raise ValueError("scroll_x and scroll_y are not in the screen")
    if scroll_page_n < 1 or scroll_once_n < 1:
        raise ValueError("scroll_page_n or scroll_once_n is not greater than 0")

    ctrl = StormworksController(
        ahk_executable_path=str(ahk_exe) if ahk_exe is not None else "",
        title=win_title,
        text=win_text,
        exclude_title=win_exclude_title,
        exclude_text=win_exclude_text,
    )
    ctrl.activate_sleep_secs = activate_sleep_secs
    ctrl.scroll_sleep_secs = scroll_sleep_secs

    ctrl.activate(sleep=True)
    try:
        ctrl.check_fullscreen()
        scr_w, scr_h = get_screen_size()
        if scr_w != screen_width or scr_h != screen_height:
            raise ValueError(f"Screen size is not {screen_width}x{screen_height}")

        ctrl.mouse_wheel(
            "up",
            x=scroll_x,
            y=scroll_y,
            n=scroll_page_n,
            sleep=True,
        )
        img = stitch_screenshot(
            ctrl.scroll_and_screenshot(
                scroll_direction="down",
                scroll_x=scroll_x,
                scroll_y=scroll_y,
                scroll_n=scroll_once_n,
                capture_output="numpy",
                capture_region=capture_region,
            ),
            template_ratio=capture_template_ratio,
            scroll_threshold=scroll_threshold,
        )
    finally:
        ctrl.minimize(sleep=False)
    return img
