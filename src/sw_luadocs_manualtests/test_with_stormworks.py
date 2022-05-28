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


def test_isfullscreen_windowed(*, win, ctrl):
    if ctrl.is_fullscreen():
        raise RuntimeError


def test_isfullscreen_fullscreen(*, win, ctrl):
    if not ctrl.is_fullscreen():
        raise RuntimeError


def test_isfullscreen_closed(*, win, ctrl):
    if ctrl.is_fullscreen():
        raise RuntimeError


def test_checkexists_windowed(*, win, ctrl):
    ctrl.check_exists()


def test_checkexists_fullscreen(*, win, ctrl):
    ctrl.check_exists()


def test_checkexists_closed(*, win, ctrl):
    try:
        ctrl.check_exists()
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test_checkfullscreen_windowed(*, win, ctrl):
    try:
        ctrl.check_fullscreen()
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test_checkfullscreen_fullscreen(*, win, ctrl):
    ctrl.check_fullscreen()


def test_checkfullscreen_closed(*, win, ctrl):
    try:
        ctrl.check_fullscreen()
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test_activate_windowed(*, win, ctrl):
    win.minimize()
    ctrl.activate()
    if not win.is_active():
        raise RuntimeError


def test_activate_fullscreen(*, win, ctrl):
    win.minimize()
    ctrl.activate()
    if not win.is_active():
        raise RuntimeError


def test_activate_closed(*, win, ctrl):
    try:
        ctrl.activate()
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test_minimize_windowed(*, win, ctrl):
    ctrl.minimize()
    if not win.is_minimized():
        raise RuntimeError


def test_minimize_fullscreen(*, win, ctrl):
    ctrl.minimize()
    if not win.is_minimized():
        raise RuntimeError


def test_minimize_closed(*, win, ctrl):
    try:
        ctrl.minimize()
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test_mousewheel_windowed(*, win, ctrl):
    try:
        ctrl.mouse_wheel("up")
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test_mousewheel_fullscreen(*, win, ctrl):
    ctrl.mouse_wheel("up")
    ctrl.mouse_wheel("up", x="0", y="0")
    ctrl.mouse_wheel("up", x=0, y=0)
    ctrl.mouse_wheel("up", x=1919, y=1079)

    for x, y, exc in [
        (-1, 0, ValueError),
        (0, -1, ValueError),
        (1920, 0, RuntimeError),
        (0, 1080, RuntimeError),
    ]:
        try:
            ctrl.mouse_wheel("up", x=x, y=y)
        except exc:
            pass
        else:
            raise RuntimeError


def test_mousewheel_closed(*, win, ctrl):
    try:
        ctrl.mouse_wheel("up")
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test(*, ahk_exe, win_title, win_text, win_exclude_title, win_exclude_text):
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

    print("----- 640x480 windowed mode -----")
    input("please set stormworks to 640x480 windowed mode manually ... ")
    for fn in [
        test_clientarea_windowed,
        test_isfullscreen_windowed,
        test_checkexists_windowed,
        test_checkfullscreen_windowed,
        test_activate_windowed,
        test_minimize_windowed,
        test_mousewheel_windowed,
    ]:
        win.activate()

        print(fn)
        try:
            fn(win=win, ctrl=ctrl)
        except Exception:
            traceback.print_exc()

    print("----- 1920x1080 fullscreen mode -----")
    input("please set stormworks to 1920x1080 fullscreen mode manually ... ")
    for fn in [
        test_clientarea_fullscreen,
        test_isfullscreen_fullscreen,
        test_checkexists_fullscreen,
        test_checkfullscreen_fullscreen,
        test_activate_fullscreen,
        test_minimize_fullscreen,
        test_mousewheel_fullscreen,
    ]:
        win.activate()

        print(fn)
        try:
            fn(win=win, ctrl=ctrl)
        except Exception:
            traceback.print_exc()

    print("----- closed -----")
    win.close()
    for fn in [
        test_isfullscreen_closed,
        test_checkexists_closed,
        test_checkfullscreen_closed,
        test_activate_closed,
        test_minimize_closed,
        test_mousewheel_closed,
    ]:
        print(fn)
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
