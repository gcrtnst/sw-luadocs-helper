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


class Selector:
    def __init__(self, *, section=None, kind=None, start=None, stop=None):
        self._section = int(section) if section is not None else None
        self._kind = dot_flatdoc.as_kind(kind) if kind is not None else None
        self._start = int(start) if start is not None else None
        self._stop = int(stop) if stop is not None else None

    def select(self, flatdoc):
        flatdoc = dot_flatdoc.as_flatdoc(flatdoc)

        idx_list = []
        section_cnt = 0
        for idx, flatelem in enumerate(flatdoc):
            if flatelem.kind == "head":
                section_cnt += 1
            if (self._section is None or section_cnt == self._section) and (
                self._kind is None or flatelem.kind == self._kind
            ):
                idx_list.append(idx)
        idx_list = idx_list[self._start : self._stop]

        sl_list = []
        for idx in idx_list:
            if len(sl_list) <= 0 or sl_list[-1].stop < idx:
                sl = slice(idx, idx + 1)
                sl_list.append(sl)
            else:
                sl = slice(sl_list[-1].start, idx + 1)
                sl_list[-1] = sl
        return sl_list


class Modifier:
    def __init__(self):
        raise NotImplementedError

    def modify(self, flatdoc):
        raise NotImplementedError


class JoinModifier(Modifier):
    def __init__(self, *, sep="\n\n"):
        self._sep = str(sep)

    def modify(self, flatdoc):
        flatdoc = dot_flatdoc.as_flatdoc(flatdoc)

        old_flatdoc = flatdoc[:]
        new_flatdoc = list(
            map(
                lambda old_flatdoc_monokind: dot_flatdoc.FlatElem(
                    txt=self._sep.join(
                        old_flatelem.txt for old_flatelem in old_flatdoc_monokind
                    ),
                    kind=old_flatdoc_monokind[0].kind,
                ),
                dot_flatdoc.split_flatdoc_by_kind(old_flatdoc),
            )
        )
        return new_flatdoc


class SplitModifier(Modifier):
    def __init__(self, *, sep="\n\n"):
        self._sep = str(sep)


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


def hint_from_dict(d):
    d = dict(d)

    op = d.get("op")
    if op == "join":
        del d["op"]
        return JoinHint(**d)
    if op == "split":
        del d["op"]
        return SplitHint(**d)
    raise ValueError


def as_hint(v):
    if isinstance(v, dict):
        v = hint_from_dict(v)
    if not isinstance(v, Hint):
        raise TypeError
    return v


def apply_hint_list(flatdoc, hint_list):
    flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
    hint_list = list(map(as_hint, hint_list))

    flatdoc = flatdoc[:]
    for hint in hint_list:
        flatdoc = hint.apply(flatdoc)
    return flatdoc
