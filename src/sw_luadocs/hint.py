import dataclasses


from . import flatdoc as dot_flatdoc


def get_section(flatdoc, sect_nth):
    flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
    sect_nth = int(sect_nth)

    start_idx_list = [0]
    for idx, flatelem in enumerate(flatdoc):
        if flatelem.kind == "head":
            start_idx_list.append(idx)
    stop_idx_list = start_idx_list[1:] + [len(flatdoc)]

    start_idx = start_idx_list[sect_nth]
    stop_idx = stop_idx_list[sect_nth]
    return flatdoc[start_idx:stop_idx]


@dataclasses.dataclass(frozen=True, kw_only=True, slots=True)
class Hint:
    def __post_init__(self):
        raise NotImplementedError

    def apply(self, flatdoc):
        raise NotImplementedError
