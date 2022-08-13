import numpy as np
import PIL.Image


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


def resize_image(img, size, *, resample=None, box=None, reducing_gap=None):
    pil = PIL.Image.fromarray(img)
    pil = pil.resize(size, resample=resample, box=box, reducing_gap=reducing_gap)
    return np.asarray(pil)


def imread(fname):
    pil = PIL.Image.open(fname)
    return np.asarray(pil)


def imsave(fname, img):
    PIL.Image.fromarray(img).save(fname)
