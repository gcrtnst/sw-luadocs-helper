import argparse
import pathlib
import pytesseract
import shlex
import toml

from . import capture as dot_capture
from . import flatdoc as dot_flatdoc
from . import image as dot_image
from . import recognize as dot_recognize


def capture_main(ns):
    cfg = toml.load(ns.config)
    capture_cfg = cfg["capture"]

    img = dot_capture.capture(
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
        capture_area=(
            capture_cfg["capture_area_x1"],
            capture_cfg["capture_area_y1"],
            capture_cfg["capture_area_x2"],
            capture_cfg["capture_area_y2"],
        ),
        capture_template_ratio=capture_cfg["capture_template_ratio"],
        activate_sleep_secs=capture_cfg["activate_sleep_secs"],
        scroll_sleep_secs=capture_cfg["scroll_sleep_secs"],
    )
    dot_image.imsave(ns.capture_file, img)


def recognize_main(ns):
    cfg = toml.load(ns.config)
    recognize_cfg = cfg["recognize"]

    if ns.tesseract_exe is not None:
        pytesseract.pytesseract.tesseract_cmd = str(ns.tesseract_exe)

    capture_img = dot_image.imread(ns.capture_file)
    flatdoc = dot_recognize.recognize(
        capture_img,
        tesseract_lang=recognize_cfg["tesseract_lang"],
        tesseract_config=shlex.join(recognize_cfg["tesseract_config"]),
        head_thresh_s=recognize_cfg["head_thresh_s"],
        body_line_h=recognize_cfg["body_line_h"],
        code_thresh_x=recognize_cfg["code_thresh_x"],
        code_base_x=recognize_cfg["code_base_x"],
        code_indent_w=recognize_cfg["code_indent_w"],
        code_line_h=recognize_cfg["code_line_h"],
        bg_thresh_rgb=(
            recognize_cfg["bg_thresh_r"],
            recognize_cfg["bg_thresh_g"],
            recognize_cfg["bg_thresh_b"],
        ),
    )
    txt = dot_flatdoc.format_mdlike(flatdoc)
    with open(ns.txt_file, mode="w", encoding="utf-8", newline="\n") as fobj:
        fobj.write(txt)


def main(*, args=None, exit_on_error=True):
    parser = argparse.ArgumentParser(exit_on_error=exit_on_error)
    parser_group = parser.add_subparsers(required=True, metavar="COMMAND")

    parser_capture = parser_group.add_parser(
        "capture", help="take screenshots of Stormworks in-game Lua API documentation"
    )
    parser_capture.set_defaults(func=capture_main)
    parser_capture.add_argument(
        "capture_file", type=pathlib.Path, help="file to save screenshots"
    )
    parser_capture.add_argument(
        "-c", "--config", type=pathlib.Path, required=True, help="configuration file"
    )
    parser_capture.add_argument(
        "--ahk-exe", type=pathlib.Path, help="AutoHotKey executable file"
    )

    parser_recognize = parser_group.add_parser(
        "recognize", help="recognizes text in captured screenshots"
    )
    parser_recognize.set_defaults(func=recognize_main)
    parser_recognize.add_argument(
        "capture_file",
        type=pathlib.Path,
        help="file of screenshots taken with the capture subcommand",
    )
    parser_recognize.add_argument(
        "txt_file", type=pathlib.Path, help="file to save character recognition results"
    )
    parser_recognize.add_argument(
        "-c", "--config", type=pathlib.Path, required=True, help="configuration file"
    )
    parser_recognize.add_argument(
        "--tesseract-exe", type=pathlib.Path, help="Tesseract OCR executable file"
    )

    ns = parser.parse_args(args=args)
    ns.func(ns)
