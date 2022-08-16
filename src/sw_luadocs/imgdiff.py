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

    def __eq__(self, other):
        if type(self) is type(other):
            return np.array_equal(self.img, other.img) and self.is_fg == other.is_fg
        return super().__eq__(other)

    def __hash__(self):
        return hash((self.img.tobytes(), self.is_fg))
