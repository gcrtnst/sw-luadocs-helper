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


def as_tesseract_tsv(v):
    if not isinstance(v, dict):
        raise TypeError("v is not dict")
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
        "conf",
        "text",
    ):
        if key not in v:
            raise KeyError(f'v["{key}"] is missing')
        if not isinstance(v[key], list):
            raise TypeError(f'v["{key}"] is not list')
        if len(v[key]) != len(v["level"]):
            raise ValueError("list lengths do not match")

    tess_tsv = {}
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
        tess_tsv[key] = list(map(int, v[key]))
    tess_tsv["conf"] = list(map(float, v["conf"]))
    tess_tsv["text"] = list(map(str, v["text"]))
    return tess_tsv


def preprocess(img):
    img = convert_image(img, dst_mode="RGB")
    return 255 - np.amax(img, axis=2)


def recognize_line(tess_tsv):
    tess_tsv = as_tesseract_tsv(tess_tsv)

    ocr_line_list = []
    idx = 0
    box = None
    conf = None
    txt = None
    while idx < len(tess_tsv["level"]):
        if tess_tsv["level"][idx] == 4:
            box = (
                tess_tsv["left"][idx],
                tess_tsv["top"][idx],
                tess_tsv["width"][idx],
                tess_tsv["height"][idx],
            )
            conf = 100.0
            idx += 1

            txt = []
            while idx < len(tess_tsv["level"]):
                if tess_tsv["level"][idx] < 5:
                    break
                elif tess_tsv["level"][idx] == 5:
                    txt.append(tess_tsv["text"][idx])
                    conf = min(conf, tess_tsv["conf"][idx])
                idx += 1
            txt = " ".join(txt)
            ocr_line = {"txt": txt, "box": box, "conf": conf}
            ocr_line_list.append(ocr_line)
        else:
            idx += 1
    return ocr_line_list
