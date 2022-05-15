import colorsys
import dataclasses
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

    @classmethod
    def iter_from_tesstsv(cls, tesstsv):
        tesstsv = as_tesstsv(tesstsv)

        idx = 0
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
            yield cls(txt=txt, box=box)


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


def as_tessline(v):
    tessline = {}
    tessline["txt"] = str(v["txt"])
    tessline["box"] = tuple(map(int, v["box"]))

    if len(tessline["box"]) != 4:
        raise ValueError('v["box"] length is invalid')
    return tessline


def preprocess_image(img):
    img = convert_image(img, dst_mode="RGB")
    return 255 - np.amax(img, axis=2)


def categorize_line(
    *, tessline, capture_img, code_thresh_x, head_thresh_s, bg_thresh_rgb
):
    tessline = as_tessline(tessline)
    capture_img = convert_image(capture_img, dst_mode="RGB")
    code_thresh_x = int(code_thresh_x)
    head_thresh_s = int(head_thresh_s)
    bg_thresh_r, bg_thresh_g, bg_thresh_b = map(int, bg_thresh_rgb)

    line_x, line_y, line_w, line_h = tessline["box"]
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


def calc_code_indent(*, line_x, base_x, space_w):
    line_x = int(line_x)
    base_x = int(base_x)
    space_w = float(space_w)

    if space_w <= 0:
        raise ValueError("space_w is less than zero")

    return max(0, round((line_x - base_x) / space_w))


def create_ocrline(
    *, tessline, capture_img, bg_thresh_rgb, head_thresh_s, code_base_x, code_space_w
):
    tessline = as_tessline(tessline)
    code_base_x = int(code_base_x)
    code_space_w = float(code_space_w)

    code_thresh_x = int(max(0, code_base_x - code_space_w / 2))
    kind = categorize_line(
        tessline=tessline,
        capture_img=capture_img,
        code_thresh_x=code_thresh_x,
        head_thresh_s=head_thresh_s,
        bg_thresh_rgb=bg_thresh_rgb,
    )

    txt = tessline["txt"]
    if kind == "code":
        indent = calc_code_indent(
            line_x=tessline["box"][0], base_x=code_base_x, space_w=code_space_w
        )
        txt = " " * indent + txt

    return OCRLine(txt=txt, kind=kind, box=tessline["box"])


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
