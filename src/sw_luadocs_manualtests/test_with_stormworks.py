import _appendpath  # noqa: F401

import sw_luadocs.capture


win_title = "Stormworks"
win_class = "GLFW30"


def test_findwindow_running():
    hwnd = sw_luadocs.capture.find_window(win_class, win_title)
    if hwnd == 0:
        raise RuntimeError


def test_findwindow_closed():
    try:
        sw_luadocs.capture.find_window(win_class, win_title)
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test():
    input("please launch stormworks manually ... ")
    input("please set stormworks to 640x480 windowed mode manually ... ")
    test_findwindow_running()

    input("please set stormworks to 1920x1080 fullscreen mode manually ... ")
    test_findwindow_running()

    input("please close stormworks manually ... ")
    test_findwindow_closed()


if __name__ == "__main__":
    test()
