import dataclasses
import itertools
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


def dumps_elem(flatelem):
    if not isinstance(flatelem, FlatElem):
        raise TypeError

    s = "[" + flatelem.kind + "]\n" + flatelem.txt
    s = s.rstrip("\n") + "\n"
    if loads_elem(s) != flatelem:
        raise ValueError
    return s


def loads(s):
    s = str(s)
    line_list = s.split(sep="\n")

    idx_list = []
    for idx, line in enumerate(line_list):
        if line.startswith("[") and line.endswith("]"):
            idx_list.append(idx)
    idx_list.append(len(line_list))
    for line in line_list[: idx_list[0]]:
        if line != "":
            raise ValueError

    flatdoc = []
    for start, stop in itertools.pairwise(idx_list):
        flatelem = loads_elem("\n".join(line_list[start:stop]))
        flatdoc.append(flatelem)
    return flatdoc


def dumps(flatdoc):
    s = "\n".join(map(dumps_elem, flatdoc))
    if loads(s) != flatdoc:
        raise ValueError
    return s
