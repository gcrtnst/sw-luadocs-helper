import dataclasses
import typing


from . import image as dot_image


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class ImagePiece:
    img: typing.Any
    is_fg: typing.Any

    def __post_init__(self):
        img = dot_image.convert_image(self.img, dst_mode="RGB")
        is_fg = bool(self.is_fg)
        if img.size <= 0:
            raise ValueError

        object.__setattr__(self, "img", img)
        object.__setattr__(self, "is_fg", is_fg)
