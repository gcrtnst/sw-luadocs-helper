import dataclasses
import typing


from . import flatdoc as dot_flatdoc


def get_section(flatdoc, section_nth=None):
    flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
    section_nth = int(section_nth) if section_nth is not None else None

    if section_nth is None:
        return flatdoc[:]

    start_idx_list = [0]
    for idx, flatelem in enumerate(flatdoc):
        if flatelem.kind == "head":
            start_idx_list.append(idx)
    stop_idx_list = start_idx_list[1:] + [len(flatdoc)]

    start_idx = start_idx_list[section_nth]
    stop_idx = stop_idx_list[section_nth]
    return flatdoc[start_idx:stop_idx]


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class Hint:
    def __post_init__(self):
        raise NotImplementedError

    def apply(self, flatdoc):
        raise NotImplementedError


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class JoinHint(Hint):
    section_nth: typing.Any
    start_idx: typing.Any
    stop_idx: typing.Any

    def __post_init__(self):
        section_nth = int(self.section_nth) if self.section_nth is not None else None
        start_idx = int(self.start_idx) if self.start_idx is not None else None
        stop_idx = int(self.stop_idx) if self.stop_idx is not None else None

        object.__setattr__(self, "section_nth", section_nth)
        object.__setattr__(self, "start_idx", start_idx)
        object.__setattr__(self, "stop_idx", stop_idx)
