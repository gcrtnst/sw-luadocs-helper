import ahk
import cv2
import d3dshot
import math
import numpy as np
import time
import win32api
import win32con
import win32gui

from . import image as dot_image


def get_screen_size():
    scr_w = win32api.GetSystemMetrics(0)
    scr_h = win32api.GetSystemMetrics(1)
    return scr_w, scr_h


def activate_window(hwnd):
    hwnd = int(hwnd)

    is_iconic = win32gui.IsIconic(hwnd)
    if hwnd != win32gui.GetForegroundWindow() and not is_iconic:
        rslt = win32gui.ShowWindow(hwnd, win32con.SW_SHOWMINIMIZED)
        if rslt == 0:
            return False
        is_iconic = True
    if is_iconic:
        rslt = win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        if rslt == 0:
            return False
    return True


def is_fullscreen(hwnd):
    hwnd = int(hwnd)
    if hwnd != win32gui.GetForegroundWindow():
        return False
    if win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_TOPMOST == 0:
        return False

    scr_w = win32api.GetSystemMetrics(0)
    scr_h = win32api.GetSystemMetrics(1)
    win_x, win_y = win32gui.ClientToScreen(hwnd, (0, 0))
    _, _, win_w, win_h = win32gui.GetClientRect(hwnd)
    return win_x == 0 and win_y == 0 and win_w == scr_w and win_h == scr_h


def send_mousewheel(hwnd, x, y, delta):
    hwnd = int(hwnd)
    x = int(x)
    y = int(y)
    delta = int(delta)

    scr_w = win32api.GetSystemMetrics(0)
    scr_h = win32api.GetSystemMetrics(1)
    if x < 0 or scr_w <= x or y < 0 or scr_h <= y:
        raise ValueError

    if not is_fullscreen(hwnd):
        raise RuntimeError

    prev_x, prev_y = win32api.GetCursorPos()
    try:
        win32api.SetCursorPos((x, y))
        win32api.mouse_event(win32con.MOUSEEVENTF_WHEEL, 0, 0, delta, 0)
    finally:
        win32api.SetCursorPos((prev_x, prev_y))


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


def capture_screenshot(capture_area=None):
    cap_x = None
    cap_y = None
    cap_w = None
    cap_h = None
    region = None
    if capture_area is not None:
        cap_x, cap_y, cap_w, cap_h = capture_area
        cap_x = int(cap_x)
        cap_y = int(cap_y)
        cap_w = int(cap_w)
        cap_h = int(cap_h)

        scr_w = win32api.GetSystemMetrics(0)
        scr_h = win32api.GetSystemMetrics(1)
        if (
            cap_x < 0
            or scr_w <= cap_x
            or cap_y < 0
            or scr_h <= cap_y
            or cap_w < 1
            or scr_w <= cap_x + cap_w - 1
            or cap_h < 1
            or scr_h <= cap_y + cap_h - 1
        ):
            raise ValueError
        region = (cap_x, cap_y, cap_x + cap_w, cap_y + cap_h)

    capture_img = screenshot(capture_output="numpy", region=region)
    capture_img = dot_image.convert_image(capture_img, dst_mode="RGB")

    if cap_w is not None or cap_h is not None:
        img_h, img_w, _ = capture_img.shape
        if img_w != cap_w or img_h != cap_h:
            raise RuntimeError
    return capture_img


class StormworksController:
    def __init__(
        self,
        *,
        ahk_exe=None,
        win_title="Stormworks",
        win_text="",
        win_exclude_title="",
        win_exclude_text="",
    ):
        self._ahk = ahk.AHK(executable_path=str(ahk_exe) if ahk_exe is not None else "")
        self._win = self._ahk.win_get(
            title=win_title,
            text=win_text,
            exclude_title=win_exclude_title,
            exclude_text=win_exclude_text,
        )
        if self._win.id == "":
            raise RuntimeError

    def hwnd(self):
        return int(self._win.id, base=16)

    def client_area(self):
        hwnd = self.hwnd()
        _, _, w, h = win32gui.GetClientRect(hwnd)
        x, y = win32gui.ClientToScreen(hwnd, (0, 0))
        return x, y, w, h

    def is_fullscreen(self):
        if not self._win.exists() or not self._win.is_always_on_top():
            return False
        scr_w, scr_h = get_screen_size()
        win_x, win_y, win_w, win_h = self.client_area()
        return win_x == 0 and win_y == 0 and win_w == scr_w and win_h == scr_h

    def check_exists(self):
        if not self._win.exists():
            raise RuntimeError

    def check_fullscreen(self):
        if not self.is_fullscreen():
            raise RuntimeError

    def activate(self):
        self.check_exists()
        self._win.activate()

    def minimize(self):
        self.check_exists()
        self._win.minimize()

    def mouse_wheel(self, direction, *, x=None, y=None, n=None):
        self.check_fullscreen()
        scr_w, scr_h = get_screen_size()
        if x is None:
            x = scr_w // 2
        if y is None:
            y = scr_h // 2

        x = int(x)
        y = int(y)

        if x < 0 or y < 0:
            raise ValueError
        if scr_w <= x or scr_h <= y:
            raise RuntimeError

        self._ahk.mouse_wheel(
            direction,
            x=x,
            y=y,
            n=n,
            relative=False,
            blocking=True,
            mode="Screen",
        )

    def screenshot(self, *, capture_area=None):
        self.check_fullscreen()

        region = None
        capture_area_x = None
        capture_area_y = None
        capture_area_w = None
        capture_area_h = None
        if capture_area is not None:
            capture_area_x, capture_area_y, capture_area_w, capture_area_h = map(
                int, capture_area
            )

            if (
                capture_area_x < 0
                or capture_area_y < 0
                or capture_area_w < 1
                or capture_area_h < 1
            ):
                raise ValueError

            scr_w, scr_h = get_screen_size()
            if (
                scr_w <= capture_area_x
                or scr_h <= capture_area_y
                or scr_w <= capture_area_x + capture_area_w - 1
                or scr_h <= capture_area_y + capture_area_h - 1
            ):
                raise RuntimeError

            region = (
                capture_area_x,
                capture_area_y,
                capture_area_x + capture_area_w,
                capture_area_y + capture_area_h,
            )

        capture_img = screenshot(capture_output="numpy", region=region)
        capture_img = dot_image.convert_image(capture_img, dst_mode="RGB")
        if capture_area_w is not None and capture_area_h is not None:
            capture_img_h, capture_img_w, _ = capture_img.shape
            if capture_img_w != capture_area_w or capture_img_h != capture_area_h:
                raise RuntimeError
        return capture_img

    def scroll_and_screenshot(
        self,
        *,
        scroll_direction="down",
        scroll_x=None,
        scroll_y=None,
        scroll_n=None,
        scroll_sleep_secs=0,
        capture_area=None,
    ):
        while True:
            yield self.screenshot(capture_area=capture_area)
            self.mouse_wheel(scroll_direction, x=scroll_x, y=scroll_y, n=scroll_n)
            time.sleep(scroll_sleep_secs)


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
    ahk_exe,
    win_title,
    win_text,
    win_exclude_title,
    win_exclude_text,
    screen_width,
    screen_height,
    scroll_x,
    scroll_y,
    scroll_page_n,
    scroll_once_n,
    scroll_threshold,
    capture_area,
    capture_template_ratio,
    activate_sleep_secs,
    scroll_sleep_secs,
):
    screen_width = int(screen_width)
    screen_height = int(screen_height)
    scroll_page_n = int(scroll_page_n)
    scroll_once_n = int(scroll_once_n)

    if (
        screen_width <= 0
        or screen_height <= 0
        or scroll_page_n <= 0
        or scroll_once_n <= 0
    ):
        raise ValueError

    ctrl = StormworksController(
        ahk_exe=ahk_exe,
        win_title=win_title,
        win_text=win_text,
        win_exclude_title=win_exclude_title,
        win_exclude_text=win_exclude_text,
    )

    ctrl.activate()
    time.sleep(activate_sleep_secs)
    try:
        ctrl.check_fullscreen()
        scr_w, scr_h = get_screen_size()
        if scr_w != screen_width or scr_h != screen_height:
            raise RuntimeError

        ctrl.mouse_wheel(
            "up",
            x=scroll_x,
            y=scroll_y,
            n=scroll_page_n,
        )
        time.sleep(scroll_sleep_secs)
        img = stitch_screenshot(
            ctrl.scroll_and_screenshot(
                scroll_direction="down",
                scroll_x=scroll_x,
                scroll_y=scroll_y,
                scroll_n=scroll_once_n,
                scroll_sleep_secs=scroll_sleep_secs,
                capture_area=capture_area,
            ),
            template_ratio=capture_template_ratio,
            scroll_threshold=scroll_threshold,
        )
    finally:
        ctrl.minimize()
    return img
