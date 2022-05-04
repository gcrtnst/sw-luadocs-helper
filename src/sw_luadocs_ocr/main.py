import argparse
import imageio.v3
import pathlib
import toml

from . import capture as capture_module


def capture_main(ns, cfg):
    capture_cfg = cfg["capture"]
    img = capture_module.capture(
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
    parser_group = parser.add_subparsers(required=True, metavar="COMMAND")

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
