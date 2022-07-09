import colorsys
import dataclasses
import math
import numpy as np
import pytesseract
import typing

from . import flatdoc as dot_flatdoc
from . import patch as dot_patch
from . import image as dot_image


def as_tesstsv(v):
    tesstsv = {}
    for key in (
        "level",
        "page_num",
        "block_num",
        "par_num",
        "line_num",
        "word_num",
        "left",
        "top",
        "width",
        "height",
    ):
        tesstsv[key] = list(map(int, v[key]))
    tesstsv["conf"] = list(map(float, v["conf"]))
    tesstsv["text"] = list(map(str, v["text"]))

    for key in tesstsv:
        if len(tesstsv[key]) != len(tesstsv["level"]):
            raise ValueError

    return tesstsv


def as_box(v):
    box_x, box_y, box_w, box_h = map(int, v)
    if box_x < 0 or box_y < 0 or box_w < 1 or box_h < 1:
        raise ValueError
    return box_x, box_y, box_w, box_h


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class TesseractLine:
    txt: typing.Any
    box: typing.Any

    def __post_init__(self):
        txt = str(self.txt)
        box = as_box(self.box)

        object.__setattr__(self, "txt", txt)
        object.__setattr__(self, "box", box)


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class OCRLine:
    txt: typing.Any
    kind: typing.Any
    box: typing.Any

    def __post_init__(self):
        txt = str(self.txt)
        kind = dot_flatdoc.as_kind(self.kind)
        box = as_box(self.box)

        object.__setattr__(self, "txt", txt)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "box", box)


def as_ocrline_list(v):
    ocrline_list = []
    for ocrline in v:
        if not isinstance(ocrline, OCRLine):
            raise TypeError
        ocrline_list.append(ocrline)
    return ocrline_list


def as_ocrline_list_monokind(v, *, kind=None):
    ocrline_list = as_ocrline_list(v)
    kind = dot_flatdoc.as_kind(kind) if kind is not None else None

    if kind is None and len(ocrline_list) > 0:
        kind = ocrline_list[0].kind
    for ocrline in ocrline_list:
        if ocrline.kind != kind:
            raise ValueError
    return ocrline_list


def preprocess_image(capture_img):
    capture_img = dot_image.convert_image(capture_img, dst_mode="RGB")
    return 255 - np.amax(capture_img, axis=2)


def categorize_line(
    *, tessline, capture_img, head_thresh_s, code_thresh_x, bg_thresh_rgb
):
    capture_img = dot_image.convert_image(capture_img, dst_mode="RGB")
    head_thresh_s = int(head_thresh_s)
    code_thresh_x = int(code_thresh_x)
    bg_thresh_r, bg_thresh_g, bg_thresh_b = map(int, bg_thresh_rgb)

    if not isinstance(tessline, TesseractLine):
        raise TypeError

    line_x, line_y, line_w, line_h = tessline.box
    capture_img_h, capture_img_w, _ = capture_img.shape
    if (
        capture_img_w <= line_x
        or capture_img_h <= line_y
        or capture_img_w <= line_x + line_w - 1
        or capture_img_h <= line_y + line_h - 1
        or capture_img_w <= 0
        or capture_img_h <= 0
        or head_thresh_s < 0
        or 255 < head_thresh_s
        or code_thresh_x < 0
        or capture_img_w <= code_thresh_x
        or bg_thresh_r < 0
        or 255 < bg_thresh_r
        or bg_thresh_g < 0
        or 255 < bg_thresh_g
        or bg_thresh_b < 0
        or 255 < bg_thresh_b
    ):
        raise ValueError

    if line_x >= code_thresh_x:
        return "code"

    capture_line_img = capture_img[line_y : line_y + line_h, line_x : line_x + line_w]
    capture_line_thresh = np.zeros(capture_line_img.shape, dtype=np.uint8)
    capture_line_thresh[:, :, 0] = bg_thresh_r
    capture_line_thresh[:, :, 1] = bg_thresh_g
    capture_line_thresh[:, :, 2] = bg_thresh_b
    capture_line_mask = np.any(
        capture_line_img > capture_line_thresh, axis=2, keepdims=True
    )
    capture_line_mask = np.broadcast_to(capture_line_mask, capture_line_img.shape)
    if not np.any(capture_line_mask):
        return "body"

    char_r, char_g, char_b = np.average(
        capture_line_img, axis=(0, 1), weights=capture_line_mask
    )
    char_h, char_l, char_s = colorsys.rgb_to_hls(
        char_r / 255, char_g / 255, char_b / 255
    )
    char_h, char_l, char_s = char_h * 255, char_l * 255, char_s * 255
    return "head" if char_s >= head_thresh_s else "body"


def calc_char_count(*, pos1, pos2, size, vmin):
    pos1 = int(pos1)
    pos2 = int(pos2)
    size = float(size)
    vmin = int(vmin)

    if pos1 < 0 or pos2 < 0 or not math.isfinite(size) or size <= 0:
        raise ValueError

    return max(vmin, round((pos2 - pos1) / size))


def group_ocrline(ocrline_list):
    ocrline_list = as_ocrline_list(ocrline_list)

    idx = 0
    sl_list = []
    while idx < len(ocrline_list):
        sl_start = idx
        sl_kind = ocrline_list[idx].kind
        while idx < len(ocrline_list) and ocrline_list[idx].kind == sl_kind:
            idx += 1
        sl_stop = idx
        sl_list.append(slice(sl_start, sl_stop))
    return sl_list


def convert_tesstsv_to_tessline(tesstsv):
    tesstsv = as_tesstsv(tesstsv)

    idx = 0
    tessline_list = []
    while idx < len(tesstsv["level"]):
        if tesstsv["level"][idx] != 4:
            idx += 1
            continue

        box = (
            tesstsv["left"][idx],
            tesstsv["top"][idx],
            tesstsv["width"][idx],
            tesstsv["height"][idx],
        )
        idx += 1

        txt = []
        while idx < len(tesstsv["level"]):
            if tesstsv["level"][idx] < 5:
                break
            if tesstsv["level"][idx] == 5:
                txt.append(tesstsv["text"][idx])
            idx += 1
        txt = " ".join(txt)
        tessline_list.append(TesseractLine(txt=txt, box=box))
    return tessline_list


def convert_tessline_to_ocrline(
    tessline,
    *,
    capture_img,
    head_thresh_s,
    code_thresh_x,
    code_base_x,
    code_indent_w,
    bg_thresh_rgb
):
    capture_img = dot_image.convert_image(capture_img, dst_mode="RGB")
    code_thresh_x = int(code_thresh_x)
    code_base_x = int(code_base_x)
    code_indent_w = float(code_indent_w)

    if not isinstance(tessline, TesseractLine):
        raise TypeError

    capture_img_h, capture_img_w, _ = capture_img.shape
    if (
        capture_img_w <= 0
        or capture_img_h <= 0
        or code_thresh_x < 0
        or capture_img_w <= code_thresh_x
        or code_base_x < 0
        or capture_img_w <= code_base_x
        or not math.isfinite(code_indent_w)
        or code_indent_w <= 0
    ):
        raise ValueError

    txt = tessline.txt
    kind = categorize_line(
        tessline=tessline,
        capture_img=capture_img,
        head_thresh_s=head_thresh_s,
        code_thresh_x=code_thresh_x,
        bg_thresh_rgb=bg_thresh_rgb,
    )
    if kind == "code":
        indent = calc_char_count(
            pos1=code_base_x,
            pos2=tessline.box[0],
            size=code_indent_w,
            vmin=0,
        )
        txt = "\t" * indent + txt

    return OCRLine(txt=txt, kind=kind, box=tessline.box)


def convert_ocrline_to_flatdoc_headonly(ocrline_list):
    ocrline_list = as_ocrline_list_monokind(ocrline_list, kind="head")
    return [
        dot_flatdoc.FlatElem(txt=ocrline.txt, kind=ocrline.kind)
        for ocrline in ocrline_list
    ]


def convert_ocrline_to_flatdoc_bodyonly(ocrline_list, *, body_line_h):
    ocrline_list = as_ocrline_list_monokind(ocrline_list, kind="body")

    idx = 0
    sl_list = []
    while idx < len(ocrline_list):
        sl_start = idx
        idx += 1
        while idx < len(ocrline_list):
            numlf = calc_char_count(
                pos1=ocrline_list[idx - 1].box[1],
                pos2=ocrline_list[idx].box[1],
                size=body_line_h,
                vmin=1,
            )
            if numlf > 1:
                break
            idx += 1
        sl_stop = idx
        sl_list.append(slice(sl_start, sl_stop))

    flatdoc = []
    for sl in sl_list:
        flatdoc.append(
            dot_flatdoc.FlatElem(
                txt=" ".join(ocrline.txt for ocrline in ocrline_list[sl]), kind="body"
            )
        )
    return flatdoc


def convert_ocrline_to_flatdoc_codeonly(ocrline_list, *, code_line_h):
    ocrline_list = as_ocrline_list_monokind(ocrline_list, kind="code")

    if len(ocrline_list) <= 0:
        return []

    txt = ocrline_list[0].txt
    for idx in range(1, len(ocrline_list)):
        numlf = calc_char_count(
            pos1=ocrline_list[idx - 1].box[1],
            pos2=ocrline_list[idx].box[1],
            size=code_line_h,
            vmin=1,
        )
        txt += "\n" * numlf + ocrline_list[idx].txt
    return [dot_flatdoc.FlatElem(txt=txt, kind="code")]


def convert_ocrline_to_flatdoc_monokind(ocrline_list, *, body_line_h, code_line_h):
    ocrline_list = as_ocrline_list_monokind(ocrline_list)

    if len(ocrline_list) <= 0:
        return []
    if ocrline_list[0].kind == "head":
        return convert_ocrline_to_flatdoc_headonly(ocrline_list)
    if ocrline_list[0].kind == "body":
        return convert_ocrline_to_flatdoc_bodyonly(
            ocrline_list, body_line_h=body_line_h
        )
    if ocrline_list[0].kind == "code":
        return convert_ocrline_to_flatdoc_codeonly(
            ocrline_list, code_line_h=code_line_h
        )
    raise RuntimeError


def convert_ocrline_to_flatdoc(ocrline_list, *, body_line_h, code_line_h):
    ocrline_list = as_ocrline_list(ocrline_list)

    flatdoc = []
    for sl in group_ocrline(ocrline_list):
        flatdoc.extend(
            convert_ocrline_to_flatdoc_monokind(
                ocrline_list[sl], body_line_h=body_line_h, code_line_h=code_line_h
            )
        )
    return flatdoc


def recognize(
    capture_img,
    *,
    tesseract_lang,
    tesseract_config,
    head_thresh_s,
    body_line_h,
    code_thresh_x,
    code_base_x,
    code_indent_w,
    code_line_h,
    bg_thresh_rgb,
    patch_list
):
    preprocess_img = preprocess_image(capture_img)
    tesstsv = pytesseract.image_to_data(
        preprocess_img,
        lang=tesseract_lang,
        config=tesseract_config,
        output_type=pytesseract.Output.DICT,
    )
    tessline_list = convert_tesstsv_to_tessline(tesstsv)
    ocrline_list = [
        convert_tessline_to_ocrline(
            tessline,
            capture_img=capture_img,
            head_thresh_s=head_thresh_s,
            code_thresh_x=code_thresh_x,
            code_base_x=code_base_x,
            code_indent_w=code_indent_w,
            bg_thresh_rgb=bg_thresh_rgb,
        )
        for tessline in tessline_list
    ]
    flatdoc = convert_ocrline_to_flatdoc(
        ocrline_list, body_line_h=body_line_h, code_line_h=code_line_h
    )
    flatdoc = dot_patch.apply_patch_list(flatdoc, patch_list)
    return flatdoc
