import cv2
import d3dshot
import math
import numpy as np
import time

from . import image as dot_image
from . import win32 as dot_win32


def activate_window(hwnd):
    hwnd = int(hwnd)

    is_iconic = dot_win32.IsIconic(hwnd)
    if hwnd != dot_win32.GetForegroundWindow() and not is_iconic:
        rslt = dot_win32.ShowWindow(hwnd, dot_win32.SW_SHOWMINIMIZED)
        if rslt == 0:
            return False
        is_iconic = True
    if is_iconic:
        rslt = dot_win32.ShowWindow(hwnd, dot_win32.SW_RESTORE)
        if rslt == 0:
            return False
    return True


def is_fullscreen_window(hwnd):
    hwnd = int(hwnd)
    if (
        False
        or (hwnd != dot_win32.GetForegroundWindow())
        or (
            dot_win32.GetWindowLong(hwnd, dot_win32.GWL_EXSTYLE)
            & dot_win32.WS_EX_TOPMOST
            == 0
        )
    ):
        return False

    scr_w = dot_win32.GetSystemMetrics(dot_win32.SM_CXSCREEN)
    scr_h = dot_win32.GetSystemMetrics(dot_win32.SM_CYSCREEN)
    win_x, win_y = dot_win32.ClientToScreen(hwnd, (0, 0))
    _, _, win_w, win_h = dot_win32.GetClientRect(hwnd)
    return win_x == 0 and win_y == 0 and win_w == scr_w and win_h == scr_h


def scroll_game(hwnd, x=None, y=None, delta=None):
    scr_w = dot_win32.GetSystemMetrics(dot_win32.SM_CXSCREEN)
    scr_h = dot_win32.GetSystemMetrics(dot_win32.SM_CYSCREEN)
    if x is None:
        x = scr_w // 2
    if y is None:
        y = scr_h // 2
    if delta is None:
        delta = -120

    hwnd = int(hwnd)
    x = int(x)
    y = int(y)
    delta = int(delta)

    if x < 0 or scr_w <= x or y < 0 or scr_h <= y:
        raise ValueError

    if not is_fullscreen_window(hwnd):
        raise RuntimeError

    dot_win32.SetCursorPos(x, y)
    dot_win32.mouse_event(dot_win32.MOUSEEVENTF_WHEEL, 0, 0, delta, 0)


def screenshot(*, capture_output="pil", region=None):
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


def capture_screen(capture_area=None):
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

        scr_w = dot_win32.GetSystemMetrics(dot_win32.SM_CXSCREEN)
        scr_h = dot_win32.GetSystemMetrics(dot_win32.SM_CYSCREEN)
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


def capture_game(hwnd, capture_area=None):
    if not is_fullscreen_window(hwnd):
        raise RuntimeError
    return capture_screen(capture_area=capture_area)


def capture_and_scroll_game(
    hwnd,
    *,
    scroll_x=None,
    scroll_y=None,
    scroll_delta=None,
    scroll_sleep_secs=0,
    capture_area=None,
):
    while True:
        yield capture_game(hwnd, capture_area=capture_area)
        scroll_game(hwnd, x=scroll_x, y=scroll_y, delta=scroll_delta)
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


def main(
    *,
    win_class,
    win_title,
    screen_width,
    screen_height,
    scroll_x,
    scroll_y,
    scroll_init_delta,
    scroll_down_delta,
    scroll_threshold,
    capture_area,
    capture_template_ratio,
    activate_sleep_secs,
    scroll_sleep_secs,
):
    win_class = str(win_class)
    win_title = str(win_title)
    screen_width = int(screen_width)
    screen_height = int(screen_height)
    scroll_init_delta = int(scroll_init_delta)
    scroll_down_delta = int(scroll_down_delta)

    if scroll_init_delta <= 0 or 0 <= scroll_down_delta:
        raise ValueError

    hwnd = dot_win32.FindWindow(win_class, win_title)
    if hwnd is None:
        raise RuntimeError

    try:
        activate_window(hwnd)
        time.sleep(activate_sleep_secs)

        if not is_fullscreen_window(hwnd):
            raise RuntimeError

        scr_w = dot_win32.GetSystemMetrics(dot_win32.SM_CXSCREEN)
        scr_h = dot_win32.GetSystemMetrics(dot_win32.SM_CYSCREEN)
        if scr_w != screen_width or scr_h != screen_height:
            raise RuntimeError

        scroll_game(hwnd, x=scroll_x, y=scroll_y, delta=scroll_init_delta)
        time.sleep(scroll_sleep_secs)

        capture_img = stitch_screenshot(
            capture_and_scroll_game(
                hwnd,
                scroll_x=scroll_x,
                scroll_y=scroll_y,
                scroll_delta=scroll_down_delta,
                scroll_sleep_secs=scroll_sleep_secs,
                capture_area=capture_area,
            ),
            template_ratio=capture_template_ratio,
            scroll_threshold=scroll_threshold,
        )
    finally:
        dot_win32.ShowWindow(hwnd, dot_win32.SW_MINIMIZE)
    return capture_img
