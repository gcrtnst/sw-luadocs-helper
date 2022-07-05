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


def as_flatdoc(v):
    flatdoc = []
    for flatelem in v:
        if not isinstance(flatelem, FlatElem):
            raise TypeError
        flatdoc.append(flatelem)
    return flatdoc


def as_flatdoc_monokind(v, *, kind=None):
    flatdoc = as_flatdoc(v)
    kind = as_kind(kind) if kind is not None else None

    if kind is None and len(flatdoc) > 0:
        kind = flatdoc[0].kind
    for flatelem in flatdoc:
        if flatelem.kind != kind:
            raise ValueError
    return flatdoc


def split_flatdoc_by_kind(flatdoc):
    flatdoc = as_flatdoc(flatdoc)

    flatdoc_monokind_list = []
    idx = 0
    while idx < len(flatdoc):
        sl_start = idx
        sl_kind = flatdoc[idx].kind
        while idx < len(flatdoc) and flatdoc[idx].kind == sl_kind:
            idx += 1
        sl_stop = idx

        flatdoc_monokind = flatdoc[sl_start:sl_stop]
        flatdoc_monokind_list.append(flatdoc_monokind)
    return flatdoc_monokind_list


def parse(s):
    s = str(s)

    line_list = s.split(sep="\n")
    if line_list[-1] == "":
        line_list = line_list[:-1]

    flatdoc = []
    for line in line_list:
        kind = line[:4]
        txt = line[5:]
        if line[4:5] not in ("", " "):
            raise ValueError
        if kind == "...." and len(flatdoc) > 0:
            flatdoc[-1] = dataclasses.replace(
                flatdoc[-1], txt=flatdoc[-1].txt + "\n" + txt
            )
            continue
        flatdoc.append(FlatElem(txt=txt, kind=kind))
    return flatdoc


def format(flatdoc):
    flatdoc = as_flatdoc(flatdoc)

    doc_line_list = []
    for flatelem in flatdoc:
        elem_line_list = flatelem.txt.split(sep="\n")
        elem_line_list[0] = flatelem.kind + " " + elem_line_list[0]
        for i in range(1, len(elem_line_list)):
            elem_line_list[i] = ".... " + elem_line_list[i]
        doc_line_list.extend(elem_line_list)
    doc_line_list.append("")
    s = "\n".join(doc_line_list)

    if parse(s) != flatdoc:
        raise ValueError
    return s
