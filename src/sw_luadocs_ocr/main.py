import argparse
import imageio.v3
import pathlib

from . import config as mdl_config
from . import capture as mdl_capture


def capture_main(cfg, *, ahk_exe=None, capture_file=None):
    if ahk_exe is not None:
        ahk_exe = str(ahk_exe)
    else:
        ahk_exe = ""
    if capture_file is not None:
        capture_file = pathlib.Path(capture_file)

    ctrl = mdl_capture.StormworksController(
        ahk_executable_path=str(ahk_exe) if ahk_exe is not None else "",
        title=cfg["win_title"],
        text=cfg["win_text"],
        exclude_title=cfg["win_exclude_title"],
        exclude_text=cfg["win_exclude_text"],
    )
    ctrl.activate_sleep_secs = cfg["activate_sleep_secs"]
    ctrl.scroll_sleep_secs = cfg["scroll_sleep_secs"]

    ctrl.activate(sleep=True)
    ctrl.check_fullscreen()
    scr_w = mdl_capture.get_system_metrics(0)
    scr_h = mdl_capture.get_system_metrics(1)
    if scr_w != cfg["screen_width"] or scr_h != cfg["screen_height"]:
        raise ValueError(
            f'Screen size is not {cfg["screen_width"]}x{cfg["screen_height"]}'
        )

    ctrl.mouse_wheel(
        "up",
        x=cfg["scroll_x"],
        y=cfg["scroll_y"],
        n=cfg["scroll_page_n"],
        sleep=True,
    )
    img = mdl_capture.stitch_screenshot(
        ctrl.scroll_and_screenshot(
            scroll_direction="down",
            scroll_x=cfg["scroll_x"],
            scroll_y=cfg["scroll_y"],
            scroll_n=cfg["scroll_once_n"],
            capture_output="numpy",
            capture_region=(
                cfg["capture_region_x1"],
                cfg["capture_region_y1"],
                cfg["capture_region_x2"],
                cfg["capture_region_y2"],
            ),
        ),
        template_ratio=cfg["capture_template_ratio"],
        scroll_threshold=cfg["scroll_threshold"],
    )
    ctrl.mouse_wheel(
        "up",
        x=cfg["scroll_x"],
        y=cfg["scroll_y"],
        n=cfg["scroll_page_n"],
        sleep=True,
    )
    ctrl.minimize(sleep=False)

    if capture_file is not None:
        imageio.v3.imwrite(capture_file, img)

    return img


def main(*, args=None, exit_on_error=True):
    argp = argparse.ArgumentParser(exit_on_error=exit_on_error)
    argp.add_argument(
        "-c", "--config", type=pathlib.Path, required=True, help="configuration file"
    )
    argp.add_argument("--ahk-exe", type=pathlib.Path, help="AutoHotKey executable file")
    argp.add_argument(
        "--capture-file", type=pathlib.Path, help="file to save screenshots"
    )

    argv = argp.parse_args(args=args)
    cfg = mdl_config.load_toml(argv.config)
    capture_main(cfg, ahk_exe=argv.ahk_exe, capture_file=argv.capture_file)
