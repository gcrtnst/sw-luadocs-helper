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

    for key in tess_tsv:
        if len(tess_tsv[key]) != len(tess_tsv["level"]):
            raise ValueError("list lengths do not match")

    return tess_tsv


def as_recognized_line(v):
    rline = {}
    rline["txt"] = str(v["txt"])
    rline["box"] = tuple(map(int, v["box"]))
    rline["conf"] = float(v["conf"])

    if len(rline["box"]) != 4:
        raise ValueError('v["box"] length is invalid')
    return rline


def as_recognized_line_list(v):
    rline_list = []
    for rline in v:
        rline = as_recognized_line(rline)
        rline_list.append(rline)
    return rline_list


def preprocess(img):
    img = convert_image(img, dst_mode="RGB")
    return 255 - np.amax(img, axis=2)


def recognize_line(tess_tsv):
    tess_tsv = as_tesseract_tsv(tess_tsv)

    rline_list = []
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
            rline = {"txt": txt, "box": box, "conf": conf}
            rline_list.append(rline)
        else:
            idx += 1
    return rline_list
