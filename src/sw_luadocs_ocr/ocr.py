import colorsys
import dataclasses
import math
import numpy as np
import PIL.Image
import typing


def convert_image(
    img,
    *,
    src_mode=None,
    dst_mode=None,
    matrix=None,
    dither=None,
    palette=PIL.Image.Palette.WEB,
    colors=256,
):
    pil = PIL.Image.fromarray(img, mode=src_mode)
    pil = pil.convert(
        mode=dst_mode, matrix=matrix, dither=dither, palette=palette, colors=colors
    )
    return np.asarray(pil)


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


def as_kind(v):
    kind = str(v)
    if kind not in ("head", "body", "code"):
        raise ValueError
    return kind


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
        kind = as_kind(self.kind)
        box = as_box(self.box)

        object.__setattr__(self, "txt", txt)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "box", box)


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class OCRParagraph:
    txt: typing.Any
    kind: typing.Any

    def __post_init__(self):
        txt = str(self.txt)
        kind = as_kind(self.kind)

        object.__setattr__(self, "txt", txt)
        object.__setattr__(self, "kind", kind)


def preprocess_image(capture_img):
    capture_img = convert_image(capture_img, dst_mode="RGB")
    return 255 - np.amax(capture_img, axis=2)


def categorize_line(
    *, tessline, capture_img, head_thresh_s, code_thresh_x, bg_thresh_rgb
):
    capture_img = convert_image(capture_img, dst_mode="RGB")
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


def tesstsv_to_tessline(tesstsv):
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


def tessline_to_ocrline(
    *, tessline, capture_img, head_thresh_s, code_base_x, code_space_w, bg_thresh_rgb
):
    capture_img = convert_image(capture_img, dst_mode="RGB")
    code_base_x = int(code_base_x)
    code_space_w = float(code_space_w)

    if not isinstance(tessline, TesseractLine):
        raise TypeError

    capture_img_h, capture_img_w, _ = capture_img.shape
    if (
        capture_img_w <= 0
        or capture_img_h <= 0
        or code_base_x < 0
        or capture_img_w <= code_base_x
        or not math.isfinite(code_space_w)
        or code_space_w <= 0
    ):
        raise ValueError

    code_thresh_x = int(code_base_x - code_space_w / 2)
    code_thresh_x = max(0, min(capture_img_w - 1, code_thresh_x))
    kind = categorize_line(
        tessline=tessline,
        capture_img=capture_img,
        head_thresh_s=head_thresh_s,
        code_thresh_x=code_thresh_x,
        bg_thresh_rgb=bg_thresh_rgb,
    )

    txt = tessline.txt
    if kind == "code":
        indent = calc_char_count(
            pos1=code_base_x,
            pos2=tessline.box[0],
            size=code_space_w,
            vmin=0,
        )
        txt = " " * indent + txt

    return OCRLine(txt=txt, kind=kind, box=tessline.box)


def create_ocrpara_list(*, ocrline_list, code_line_h):
    ocrline_list = list(ocrline_list)
    for ocrline in ocrline_list:
        if not isinstance(ocrline, OCRLine):
            raise TypeError
    code_line_h = float(code_line_h)

    ocrpara_list = []
    idx = 0
    while idx < len(ocrline_list):
        kind = ocrline_list[idx].kind

        txt = None
        if kind == "head":
            txt = ocrline_list[idx].txt
            idx += 1
        else:
            idx_start = idx
            idx_end = idx
            idx += 1
            while idx < len(ocrline_list) and ocrline_list[idx].kind == kind:
                idx_end = idx
                idx += 1

            if kind == "body":
                txt = " ".join(
                    ocrline.txt for ocrline in ocrline_list[idx_start : idx_end + 1]
                )
            else:
                txt = ocrline_list[idx_start].txt
                for idx_sub in range(idx_start + 1, idx_end + 1):
                    ocrline_prev_y = ocrline_list[idx_sub - 1].box[1]
                    ocrline_curr_y = ocrline_list[idx_sub].box[1]
                    num_lf = round((ocrline_curr_y - ocrline_prev_y) / code_line_h)
                    num_lf = max(1, num_lf)
                    txt += "\n" * num_lf + ocrline_list[idx_sub].txt

        ocrpara = OCRParagraph(txt=txt, kind=kind)
        ocrpara_list.append(ocrpara)
    return ocrpara_list
