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


def preprocess(img):
    img = convert_image(img, dst_mode="RGB")
    return 255 - np.amax(img, axis=2)


def parse_tesseract_data(data):
    if not isinstance(data, dict):
        raise TypeError("data is not dict")
    for key in "level", "left", "top", "width", "height", "text":
        if key not in data:
            raise KeyError(f'data["{key}"] is missing')
        if not isinstance(data[key], list):
            raise TypeError(f'data["{key}"] is not list')
        if len(data[key]) != len(data["level"]):
            raise ValueError("list lengths do not match")

    ocr_line_list = []
    idx = 0
    box = None
    txt = None
    while idx < len(data["level"]):
        if data["level"][idx] == 4:
            box = (
                data["left"][idx],
                data["top"][idx],
                data["width"][idx],
                data["height"][idx],
            )
            idx += 1

            txt = []
            while idx < len(data["level"]):
                if data["level"][idx] < 5:
                    break
                elif data["level"][idx] == 5:
                    txt.append(data["text"][idx])
                idx += 1
            txt = " ".join(txt)
            ocr_line = {"txt": txt, "box": box}
            ocr_line_list.append(ocr_line)
        else:
            idx += 1
    return ocr_line_list
