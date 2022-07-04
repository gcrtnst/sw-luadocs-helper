import dataclasses
import typing


from . import flatdoc as dot_flatdoc


def get_section(flatdoc, section_nth=None):
    flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
    section_nth = int(section_nth) if section_nth is not None else None

    if section_nth is None:
        return slice(None, None)

    start_idx_list = [0]
    for idx, flatelem in enumerate(flatdoc):
        if flatelem.kind == "head":
            start_idx_list.append(idx)
    stop_idx_list = start_idx_list[1:] + [len(flatdoc)]

    start_idx = start_idx_list[section_nth]
    stop_idx = stop_idx_list[section_nth]
    return slice(start_idx, stop_idx)


def join_flatelem(flatdoc, *, sep="\n\n"):
    flatdoc = dot_flatdoc.as_flatdoc_monokind(flatdoc)
    sep = str(sep)

    if len(flatdoc) <= 0:
        raise ValueError

    kind = flatdoc[0].kind
    txt = sep.join(flatelem.txt for flatelem in flatdoc)
    return dot_flatdoc.FlatElem(txt=txt, kind=kind)


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class Hint:
    def __post_init__(self):
        raise NotImplementedError

    def apply(self, flatdoc):
        raise NotImplementedError


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class JoinHint(Hint):
    section_nth: typing.Any = None
    start_idx: typing.Any = None
    stop_idx: typing.Any = None
    sep: typing.Any = "\n\n"

    def __post_init__(self):
        section_nth = int(self.section_nth) if self.section_nth is not None else None
        start_idx = int(self.start_idx) if self.start_idx is not None else None
        stop_idx = int(self.stop_idx) if self.stop_idx is not None else None
        sep = str(self.sep)

        object.__setattr__(self, "section_nth", section_nth)
        object.__setattr__(self, "start_idx", start_idx)
        object.__setattr__(self, "stop_idx", stop_idx)
        object.__setattr__(self, "sep", sep)

    def apply(self, flatdoc):
        flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
        flatdoc = flatdoc[:]

        sl_sect = get_section(flatdoc, self.section_nth)
        sl_part = slice(self.start_idx, self.stop_idx)

        flatsect = flatdoc[sl_sect]
        flatpart = flatsect[sl_part]
        flatpart = [join_flatelem(flatpart, sep=self.sep)]
        flatsect[sl_part] = flatpart
        flatdoc[sl_sect] = flatsect
        return flatdoc
