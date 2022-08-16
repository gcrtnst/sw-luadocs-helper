import numpy as np


from . import image as dot_image


class ImagePiece:
    def __init__(self, *, img, is_fg):
        img = dot_image.convert_image(img, dst_mode="RGB")
        is_fg = bool(is_fg)

        if img.size <= 0:
            raise ValueError
        img = np.copy(img, order="C")
        img.flags.writeable = False

        self._img = img
        self._is_fg = is_fg

    img = property(lambda self: self._img.view())
    is_fg = property(lambda self: self._is_fg)

    def __repr__(self):
        return f"{type(self).__name__}(img={repr(self.img)}, is_fg={repr(self.is_fg)})"

    def __eq__(self, other):
        if type(self) is type(other):
            return np.array_equal(self.img, other.img) and self.is_fg == other.is_fg
        return super().__eq__(other)

    def __hash__(self):
        return hash((self.img.tobytes(), self.is_fg))


def split_image_into_pieces(capture_img, *, fg_mergin_h, bg_thresh_rgb):
    capture_img = dot_image.convert_image(capture_img, dst_mode="RGB")
    fg_mergin_h = int(fg_mergin_h)
    bg_thresh_r, bg_thresh_g, bg_thresh_b = bg_thresh_rgb
    bg_thresh_r = int(bg_thresh_r)
    bg_thresh_g = int(bg_thresh_g)
    bg_thresh_b = int(bg_thresh_b)

    img_h, img_w, _ = capture_img.shape
    if (
        fg_mergin_h < 0
        or bg_thresh_r < 0
        or 255 < bg_thresh_r
        or bg_thresh_g < 0
        or 255 < bg_thresh_g
        or bg_thresh_b < 0
        or 255 < bg_thresh_b
    ):
        raise ValueError
    if capture_img.size <= 0:
        return []

    is_fg_list = [False] * img_h
    for img_y in range(img_h):
        line_img = capture_img[img_y]
        line_r, line_g, line_b = np.amax(line_img, axis=0)
        is_fg = line_r > bg_thresh_r or line_g > bg_thresh_g or line_b > bg_thresh_b
        is_fg_list[img_y] = is_fg

    img_y = 0
    while img_y < img_h:
        if is_fg_list[img_y]:
            img_y += 1
            continue

        start_y = img_y
        while img_y < img_h and not is_fg_list[img_y]:
            img_y += 1
        stop_y = img_y

        if stop_y - start_y <= fg_mergin_h:
            for sub_y in range(start_y, stop_y):
                is_fg_list[sub_y] = True

    ipc_list = []
    img_y = 0
    while img_y < img_h:
        start_y = img_y
        is_fg = is_fg_list[start_y]
        while img_y < img_h and is_fg_list[img_y] == is_fg:
            img_y += 1
        stop_y = img_y

        ipc = ImagePiece(img=capture_img[start_y:stop_y], is_fg=is_fg)
        ipc_list.append(ipc)
    return ipc_list
