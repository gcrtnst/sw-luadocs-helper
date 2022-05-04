import argparse
import imageio.v3
import pathlib
import toml

from . import capture as capture_module


def capture_proc(
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

    ctrl = capture_module.StormworksController(
        ahk_executable_path=str(ahk_exe) if ahk_exe is not None else "",
        title=win_title,
        text=win_text,
        exclude_title=win_exclude_title,
        exclude_text=win_exclude_text,
    )
    ctrl.activate_sleep_secs = activate_sleep_secs
    ctrl.scroll_sleep_secs = scroll_sleep_secs

    ctrl.activate(sleep=True)
    ctrl.check_fullscreen()
    scr_w = capture_module.get_system_metrics(0)
    scr_h = capture_module.get_system_metrics(1)
    if scr_w != screen_width or scr_h != screen_height:
        raise ValueError(f"Screen size is not {screen_width}x{screen_height}")

    ctrl.mouse_wheel(
        "up",
        x=scroll_x,
        y=scroll_y,
        n=scroll_page_n,
        sleep=True,
    )
    img = capture_module.stitch_screenshot(
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
    ctrl.mouse_wheel(
        "up",
        x=scroll_x,
        y=scroll_y,
        n=scroll_page_n,
        sleep=True,
    )
    ctrl.minimize(sleep=False)
    return img


def capture_main(ns, cfg):
    capture_cfg = cfg["capture"]
    img = capture_proc(
        ahk_exe=ns.ahk_exe,
        win_title=capture_cfg["win_title"],
        win_text=capture_cfg["win_text"],
        win_exclude_title=capture_cfg["win_exclude_title"],
        win_exclude_text=capture_cfg["win_exclude_text"],
        screen_width=capture_cfg["screen_width"],
        screen_height=capture_cfg["screen_height"],
        scroll_x=capture_cfg["scroll_x"],
        scroll_y=capture_cfg["scroll_y"],
        scroll_page_n=capture_cfg["scroll_page_n"],
        scroll_once_n=capture_cfg["scroll_once_n"],
        scroll_threshold=capture_cfg["scroll_threshold"],
        capture_region=(
            capture_cfg["capture_region_x1"],
            capture_cfg["capture_region_y1"],
            capture_cfg["capture_region_x2"],
            capture_cfg["capture_region_y2"],
        ),
        capture_template_ratio=capture_cfg["capture_template_ratio"],
        activate_sleep_secs=capture_cfg["activate_sleep_secs"],
        scroll_sleep_secs=capture_cfg["scroll_sleep_secs"],
    )
    imageio.v3.imwrite(ns.capture_file, img)


def main(*, args=None, exit_on_error=True):
    parser = argparse.ArgumentParser(exit_on_error=exit_on_error)
    parser.add_argument(
        "-c", "--config", type=pathlib.Path, required=True, help="configuration file"
    )
    parser_group = parser.add_subparsers(required=True)

    parser_capture = parser_group.add_parser(
        "capture", help="capture Stormworks in-game Lua API documentation"
    )
    parser_capture.set_defaults(func=capture_main)
    parser_capture.add_argument(
        "--capture-file",
        type=pathlib.Path,
        help="file to save screenshots",
        required=True,
    )
    parser_capture.add_argument(
        "--ahk-exe", type=pathlib.Path, help="AutoHotKey executable file"
    )

    ns = parser.parse_args(args=args)
    cfg = toml.load(ns.config)
    ns.func(ns, cfg)
