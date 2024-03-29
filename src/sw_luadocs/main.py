import argparse
import os
import pathlib
import pytesseract
import tomli as tomllib

from . import capture as dot_capture
from . import extract as dot_extract
from . import flatdoc as dot_flatdoc
from . import image as dot_image
from . import recognize as dot_recognize
from . import which as dot_which


def parse_newline_argument(s):
    s = str(s)
    l = s.upper()

    if l == "LF":
        return "\n"
    if l == "CR":
        return "\r"
    if l == "CRLF":
        return "\r\n"
    raise ValueError


def capture(*, capture_file, cfg_file):
    with open(cfg_file, mode="rb") as fobj:
        cfg = tomllib.load(fobj)
    capture_cfg = cfg["capture"]

    img = dot_capture.main(
        screen_width=capture_cfg["screen_width"],
        screen_height=capture_cfg["screen_height"],
        scroll_x=capture_cfg["scroll_x"],
        scroll_y=capture_cfg["scroll_y"],
        scroll_init_delta=capture_cfg["scroll_init_delta"],
        scroll_down_delta=capture_cfg["scroll_down_delta"],
        scroll_threshold=capture_cfg["scroll_threshold"],
        capture_area=(
            capture_cfg["capture_area_x"],
            capture_cfg["capture_area_y"],
            capture_cfg["capture_area_w"],
            capture_cfg["capture_area_h"],
        ),
        capture_template_ratio=capture_cfg["capture_template_ratio"],
        activate_delay=capture_cfg["activate_delay"],
        scroll_mouse_delay=capture_cfg["scroll_mouse_delay"],
        scroll_smooth_delay=capture_cfg["scroll_smooth_delay"],
    )
    dot_image.imsave(capture_file, img)


def recognize(*, capture_path, recognize_path, cfg_file, tesseract_exe):
    with open(cfg_file, mode="rb") as fobj:
        cfg = tomllib.load(fobj)
    recognize_cfg = cfg["recognize"]

    if tesseract_exe is not None:
        pytesseract.pytesseract.tesseract_cmd = str(tesseract_exe)

    capture_path = pathlib.Path(capture_path)
    if not capture_path.is_dir():
        recognize_one(
            capture_file=capture_path,
            recognize_file=recognize_path,
            recognize_cfg=recognize_cfg,
        )
        return

    for capture_file in capture_path.iterdir():
        if not capture_file.is_file():
            continue
        recognize_file = pathlib.Path(recognize_path, capture_file.stem + ".txt")
        recognize_one(
            capture_file=capture_file,
            recognize_file=recognize_file,
            recognize_cfg=recognize_cfg,
        )


def recognize_one(*, capture_file, recognize_file, recognize_cfg):
    recognize_cfg = dict(recognize_cfg)

    capture_img = dot_image.imread(capture_file)
    flatdoc = dot_recognize.main(
        capture_img,
        preprocess_scale=recognize_cfg["preprocess_scale"],
        tesseract_lang=recognize_cfg["tesseract_lang"],
        body_line_h=recognize_cfg["body_line_h"],
        code_thresh_x=recognize_cfg["code_thresh_x"],
        code_base_x=recognize_cfg["code_base_x"],
        code_indent_w=recognize_cfg["code_indent_w"],
        code_line_h=recognize_cfg["code_line_h"],
    )
    txt = dot_flatdoc.format(flatdoc)
    with open(recognize_file, mode="w", encoding="utf-8", newline="\n") as fobj:
        fobj.write(txt)


def extract(*, recognize_path, extract_path, stormworks_exe):
    with open(stormworks_exe, mode="rb") as fobj:
        exe_bin = fobj.read()

    recognize_path = pathlib.Path(recognize_path)
    if not recognize_path.is_dir():
        extract_one(
            recognize_file=recognize_path,
            extract_file=extract_path,
            exe_bin=exe_bin,
        )
        return

    for recognize_file in recognize_path.iterdir():
        if not recognize_file.is_file():
            continue
        extract_file = pathlib.Path(extract_path, recognize_file.name)
        extract_one(
            recognize_file=recognize_file,
            extract_file=extract_file,
            exe_bin=exe_bin,
        )


def extract_one(*, recognize_file, extract_file, exe_bin):
    with open(recognize_file, mode="r", encoding="utf-8", newline="\n") as fobj:
        ocr_txt = fobj.read()

    ocr_flatdoc = dot_flatdoc.parse(ocr_txt)
    ext_flatdoc = dot_extract.main(
        ocr_flatdoc,
        exe_bin,
        body_sep="\n\n",
        code_sep="\n\n",
    )
    ext_txt = dot_flatdoc.format(ext_flatdoc)

    with open(extract_file, mode="w", encoding="utf-8", newline="\n") as fobj:
        fobj.write(ext_txt)


def export(*, load_path, save_path, markup, encoding, newline):
    load_path = pathlib.Path(load_path)
    if not load_path.is_dir():
        export_one(
            load_file=load_path,
            save_file=save_path,
            markup=markup,
            encoding=encoding,
            newline=newline,
        )
        return

    suffix = ".txt"
    if markup == "markdown":
        suffix = ".md"

    for load_file in load_path.iterdir():
        if not load_file.is_file():
            continue
        save_file = pathlib.Path(save_path, load_file.name)
        save_file = save_file.with_suffix(suffix)
        export_one(
            load_file=load_file,
            save_file=save_file,
            markup=markup,
            encoding=encoding,
            newline=newline,
        )


def export_one(*, load_file, save_file, markup, encoding, newline):
    with open(load_file, mode="r", encoding="utf-8", newline="\n") as fobj:
        load_txt = fobj.read()
    flatdoc = dot_flatdoc.parse(load_txt)
    save_txt = dot_flatdoc.export(flatdoc, markup)
    with open(save_file, mode="w", encoding=encoding, newline=newline) as fobj:
        fobj.write(save_txt)


def main(*, args=None, exit_on_error=True):
    parser = argparse.ArgumentParser(exit_on_error=exit_on_error)
    parser_group = parser.add_subparsers(
        required=True, dest="command", metavar="command"
    )

    parser_capture = parser_group.add_parser("capture", help="")
    parser_capture.add_argument("capture_file", type=pathlib.Path)
    parser_capture.add_argument("-c", "--config", type=pathlib.Path, required=True)

    parser_recognize = parser_group.add_parser("recognize", help="")
    parser_recognize.add_argument("capture_path", type=pathlib.Path)
    parser_recognize.add_argument("recognize_path", type=pathlib.Path)
    parser_recognize.add_argument("-c", "--config", type=pathlib.Path, required=True)
    parser_recognize.add_argument(
        "--tesseract-exe",
        type=pathlib.Path,
        default=dot_which.tesseract(),
    )

    parser_extract = parser_group.add_parser("extract", help="")
    parser_extract.add_argument("recognize_path", type=pathlib.Path)
    parser_extract.add_argument("extract_path", type=pathlib.Path)
    parser_extract.add_argument(
        "--stormworks-exe",
        type=pathlib.Path,
        default=dot_which.stormworks(mode=os.F_OK | os.R_OK),
    )

    parser_export = parser_group.add_parser("export", help="")
    parser_export.add_argument("load_path", type=pathlib.Path)
    parser_export.add_argument("save_path", type=pathlib.Path)
    parser_export.add_argument(
        "-f",
        "--format",
        default="markdown",
        dest="markup",
        metavar="FORMAT",
    )
    parser_export.add_argument("--encoding", default="utf-8")
    parser_export.add_argument("--newline", default="LF", type=parse_newline_argument)

    ns = parser.parse_args(args=args)
    if ns.command == "capture":
        return capture(
            capture_file=ns.capture_file,
            cfg_file=ns.config,
        )
    if ns.command == "recognize":
        return recognize(
            capture_path=ns.capture_path,
            recognize_path=ns.recognize_path,
            cfg_file=ns.config,
            tesseract_exe=ns.tesseract_exe,
        )
    if ns.command == "extract":
        return extract(
            recognize_path=ns.recognize_path,
            extract_path=ns.extract_path,
            stormworks_exe=ns.stormworks_exe,
        )
    if ns.command == "export":
        return export(
            load_path=ns.load_path,
            save_path=ns.save_path,
            markup=ns.markup,
            encoding=ns.encoding,
            newline=ns.newline,
        )
    raise RuntimeError
