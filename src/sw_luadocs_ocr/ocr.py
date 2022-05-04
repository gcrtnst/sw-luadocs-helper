import numpy as np
import PIL.Image
import PIL.ImageOps


def preprocess(img):
    pil = PIL.Image.fromarray(img)
    pil = PIL.ImageOps.invert(pil)
    return np.array(pil)
