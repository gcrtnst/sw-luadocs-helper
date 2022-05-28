import _appendpath  # noqa: F401

import ahk
import argparse
import pathlib
import sw_luadocs.capture
import traceback


def test_clientarea_windowed(*, win, ctrl):
    win.move(x=100, y=200)
    win_x1, win_y1, win_w1, win_h1 = ctrl.client_area()
    if not (win_w1 == 640 and win_h1 == 480):
        raise RuntimeError

    win.move(x=200, y=100)
    win_x2, win_y2, win_w2, win_h2 = ctrl.client_area()
    if not (
        win_x2 == win_x1 + 100
        and win_y2 == win_y1 - 100
        and win_w1 == 640
        and win_h1 == 480
    ):
        raise RuntimeError


def test_clientarea_fullscreen(*, win, ctrl):
    win_x, win_y, win_w, win_h = ctrl.client_area()
    if not (win_x == 0 and win_y == 0 and win_w == 1920 and win_h == 1080):
        raise RuntimeError


def test(*, ahk_exe, win_title, win_text, win_exclude_title, win_exclude_text):
    input("launch stormworks --> ")
    win = ahk.AHK().win_get(
        title=win_title,
        text=win_text,
        exclude_title=win_exclude_title,
        exclude_text=win_exclude_text,
    )
    ctrl = sw_luadocs.capture.StormworksController(
        ahk_exe=ahk_exe,
        win_title=win_title,
        win_text=win_text,
        win_exclude_title=win_exclude_title,
        win_exclude_text=win_exclude_text,
    )
    ctrl.activate_sleep_secs = 5
    ctrl.scroll_sleep_secs = 5
    ctrl.minimize_sleep_secs = 5

    input("set to 640x480 windowed mode --> ")
    for fn in [test_clientarea_windowed]:
        win.activate()
        try:
            fn(win=win, ctrl=ctrl)
        except Exception:
            traceback.print_exc()

    input("set to 1920x1080 fullscreen mode --> ")
    for fn in [test_clientarea_fullscreen]:
        win.activate()
        try:
            fn(win=win, ctrl=ctrl)
        except Exception:
            traceback.print_exc()

    win.close()
    for fn in []:
        try:
            fn(win=win, ctrl=ctrl)
        except Exception:
            traceback.print_exc()


def main():
    argp = argparse.ArgumentParser()
    argp.add_argument("--ahk-exe", type=pathlib.Path)
    argp.add_argument("--win-title", default="Stormworks")
    argp.add_argument("--win-text", default="")
    argp.add_argument("--win-exclude-title", default="")
    argp.add_argument("--win-exclude-text", default="")
    args = argp.parse_args()

    test(
        ahk_exe=args.ahk_exe,
        win_title=args.win_title,
        win_text=args.win_text,
        win_exclude_title=args.win_exclude_title,
        win_exclude_text=args.win_exclude_text,
    )


if __name__ == "__main__":
    main()
