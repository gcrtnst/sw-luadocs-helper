import _appendpath  # noqa: F401

import sw_luadocs.capture


def test_checkwindowexists_running(hwnd):
    sw_luadocs.capture.check_window_exists(hwnd)


def test_checkwindowexists_closed(hwnd):
    try:
        sw_luadocs.capture.check_window_exists(hwnd)
    except RuntimeError:
        pass
    else:
        raise RuntimeError


def test():
    input("please launch stormworks manually ... ")
    hwnd = sw_luadocs.capture.find_window("GLFW30", "Stormworks")

    input("please set stormworks to 640x480 windowed mode manually ... ")
    test_checkwindowexists_running(hwnd)

    input("please set stormworks to 1920x1080 fullscreen mode manually ... ")
    test_checkwindowexists_running(hwnd)

    input("please close stormworks manually ... ")
    test_checkwindowexists_closed(hwnd)


if __name__ == "__main__":
    test()
