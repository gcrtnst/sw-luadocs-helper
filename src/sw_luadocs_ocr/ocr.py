import colorsys
import numpy as np
import PIL.Image


def convert_image(
    img,
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
            raise ValueError("list lengths do not match")

    return tesstsv


def as_tessline(v):
    tessline = {}
    tessline["txt"] = str(v["txt"])
    tessline["box"] = tuple(map(int, v["box"]))

    if len(tessline["box"]) != 4:
        raise ValueError('v["box"] length is invalid')
    return tessline


def preprocess(img):
    img = convert_image(img, dst_mode="RGB")
    return 255 - np.amax(img, axis=2)


def combine_tesstsv_into_tessline(tesstsv):
    tesstsv = as_tesstsv(tesstsv)

    idx = 0
    box = None
    txt = None
    while idx < len(tesstsv["level"]):
        if tesstsv["level"][idx] == 4:
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
                elif tesstsv["level"][idx] == 5:
                    txt.append(tesstsv["text"][idx])
                idx += 1
            txt = " ".join(txt)
            yield {"txt": txt, "box": box}
        else:
            idx += 1


def categorize_tessline(
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
