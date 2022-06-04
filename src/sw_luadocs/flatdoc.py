import dataclasses
import typing


def as_kind(v):
    kind = str(v)
    if kind not in ("head", "body", "code"):
        raise ValueError
    return kind


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class FlatElem:
    txt: typing.Any
    kind: typing.Any

    def __post_init__(self):
        txt = str(self.txt)
        kind = as_kind(self.kind)

        object.__setattr__(self, "txt", txt)
        object.__setattr__(self, "kind", kind)


def loads_elem(s):
    s = str(s)
    line_list = s.split(sep="\n")

    if not (line_list[0].startswith("[") and line_list[0].endswith("]")):
        raise ValueError
    kind = line_list[0][1:-1]

    line_list_end = len(line_list) - 1
    while line_list_end >= 1:
        if line_list[line_list_end] != "":
            break
        line_list_end -= 1
    txt = "\n".join(line_list[1 : line_list_end + 1])
    return FlatElem(txt=txt, kind=kind)
