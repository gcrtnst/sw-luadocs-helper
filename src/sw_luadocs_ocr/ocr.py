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
