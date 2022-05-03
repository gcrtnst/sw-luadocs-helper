import cv2
import numpy as np


def calc_scroll_amount(old_img, new_img, *, template_ratio=0.25):
    old_img = np.asarray(old_img, dtype=np.float32)
    new_img = np.asarray(new_img, dtype=np.float32)
    template_ratio = float(template_ratio)

    if old_img.shape != new_img.shape:
        raise ValueError("Image shape does not match")
    if old_img.ndim < 2 or 3 < old_img.ndim:
        raise ValueError("The given data is not an image")
    if old_img.size <= 0:
        raise ValueError("The image is empty")
    if template_ratio < 0 or 1 < template_ratio:
        raise ValueError("template_ratio is not within the range 0~1")

    template_height = int(old_img.shape[0] * template_ratio)
    if template_height <= 0:
        template_height = 1
    template_old_y = (old_img.shape[0] - template_height) // 2
    template = old_img[template_old_y : template_old_y + template_height]
    cor = cv2.matchTemplate(new_img, template, cv2.TM_CCOEFF)
    template_new_y = np.reshape(np.argmax(cor, axis=0), 1)[0]
    return template_new_y - template_old_y


def stitch_screenshot(iterable, *, template_ratio=0.25, scroll_threshold=0):
    scroll_threshold = int(scroll_threshold)
    if scroll_threshold < 0:
        raise ValueError("scroll_threshold is less than 0")

    old_img = None
    gen_img = None
    for new_img in iterable:
        new_img = np.asarray(new_img)
        if old_img is None:
            old_img = new_img
            gen_img = new_img
            continue

        scroll_amount = calc_scroll_amount(
            old_img, new_img, template_ratio=template_ratio
        )
        scroll_pixels = -scroll_amount
        if scroll_pixels <= scroll_threshold:
            break

        tmp_shape = list(gen_img.shape)
        tmp_shape[0] += scroll_pixels
        tmp_shape = tuple(tmp_shape)
        tmp_order = "F" if gen_img.flags.f_contiguous else "C"
        tmp_img = np.zeros(tmp_shape, dtype=gen_img.dtype, order=tmp_order)
        tmp_img[:-scroll_pixels] = gen_img
        tmp_img[-scroll_pixels:] = new_img[-scroll_pixels:]

        old_img = new_img
        gen_img = tmp_img
    return gen_img
