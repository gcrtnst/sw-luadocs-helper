import dataclasses
import typing


from . import flatdoc as dot_flatdoc


def get_section(flatdoc, section_nth=None):
    flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
    section_nth = int(section_nth) if section_nth is not None else None

    if section_nth is None:
        return slice(None, None)

    start_idx_list = [0]
    for elem_idx, flatelem in enumerate(flatdoc):
        if flatelem.kind == "head":
            start_idx_list.append(elem_idx)
    stop_idx_list = start_idx_list[1:] + [len(flatdoc)]

    elem_start_idx = start_idx_list[section_nth]
    elem_stop_idx = stop_idx_list[section_nth]
    return slice(elem_start_idx, elem_stop_idx)


def join_flatelem(flatdoc, *, sep="\n\n"):
    flatdoc = dot_flatdoc.as_flatdoc_monokind(flatdoc)
    sep = str(sep)

    if len(flatdoc) <= 0:
        raise ValueError

    kind = flatdoc[0].kind
    txt = sep.join(flatelem.txt for flatelem in flatdoc)
    return dot_flatdoc.FlatElem(txt=txt, kind=kind)


def split_flatelem(flatelem, txt_pos):
    txt_pos = int(txt_pos)
    if not isinstance(flatelem, dot_flatdoc.FlatElem):
        raise TypeError

    txt1 = flatelem.txt[:txt_pos]
    txt2 = flatelem.txt[txt_pos:]
    if txt1 == "" or txt2 == "":
        raise ValueError

    return [
        dot_flatdoc.FlatElem(txt=txt1, kind=flatelem.kind),
        dot_flatdoc.FlatElem(txt=txt2, kind=flatelem.kind),
    ]


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class Hint:
    def __post_init__(self):
        raise NotImplementedError

    def apply(self, flatdoc):
        raise NotImplementedError


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class JoinHint(Hint):
    section_nth: typing.Any = None
    elem_start_idx: typing.Any = None
    elem_stop_idx: typing.Any = None
    sep: typing.Any = "\n\n"

    def __post_init__(self):
        section_nth = int(self.section_nth) if self.section_nth is not None else None
        elem_start_idx = (
            int(self.elem_start_idx) if self.elem_start_idx is not None else None
        )
        elem_stop_idx = (
            int(self.elem_stop_idx) if self.elem_stop_idx is not None else None
        )
        sep = str(self.sep)

        object.__setattr__(self, "section_nth", section_nth)
        object.__setattr__(self, "elem_start_idx", elem_start_idx)
        object.__setattr__(self, "elem_stop_idx", elem_stop_idx)
        object.__setattr__(self, "sep", sep)

    def apply(self, flatdoc):
        flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
        flatdoc = flatdoc[:]

        sl_sect = get_section(flatdoc, self.section_nth)
        sl_part = slice(self.elem_start_idx, self.elem_stop_idx)

        flatsect = flatdoc[sl_sect]
        flatpart = flatsect[sl_part]
        flatpart = [join_flatelem(flatpart, sep=self.sep)]
        flatsect[sl_part] = flatpart
        flatdoc[sl_sect] = flatsect
        return flatdoc


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class SplitHint(Hint):
    section_nth: typing.Any = None
    elem_idx: typing.Any
    txt_pos: typing.Any

    def __post_init__(self):
        section_nth = int(self.section_nth) if self.section_nth is not None else None
        elem_idx = int(self.elem_idx)
        txt_pos = int(self.txt_pos)

        object.__setattr__(self, "section_nth", section_nth)
        object.__setattr__(self, "elem_idx", elem_idx)
        object.__setattr__(self, "txt_pos", txt_pos)

    def apply(self, flatdoc):
        flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
        flatdoc = flatdoc[:]

        sl = get_section(flatdoc, self.section_nth)
        flatsect = flatdoc[sl]

        elem_idx = self.elem_idx
        if elem_idx < 0:
            elem_idx += len(flatsect)
        if elem_idx < 0 or len(flatsect) <= elem_idx:
            raise IndexError
        flatsect[elem_idx : elem_idx + 1] = split_flatelem(
            flatsect[elem_idx], self.txt_pos
        )

        flatdoc[sl] = flatsect
        return flatdoc
