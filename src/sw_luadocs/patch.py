import re


from . import flatdoc as dot_flatdoc


def as_pattern(v, flags=0):
    if isinstance(v, re.Pattern):
        return v
    if isinstance(v, str) or isinstance(v, bytes):
        return re.compile(v, flags=flags)
    raise TypeError


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
        if self._sep == "":
            raise ValueError

    def modify(self, flatdoc):
        flatdoc = dot_flatdoc.as_flatdoc(flatdoc)

        old_flatdoc = flatdoc[:]
        new_flatdoc = []
        for old_flatelem in old_flatdoc:
            for txt in old_flatelem.txt.split(sep=self._sep):
                new_flatelem = dot_flatdoc.FlatElem(txt=txt, kind=old_flatelem.kind)
                new_flatdoc.append(new_flatelem)
        return new_flatdoc


class LineSplitModifier(Modifier):
    def __init__(self, *, keyword_set=None):
        if keyword_set is None:
            keyword_set = set()
        self._keyword_set = set(map(str, keyword_set))


class Patch:
    def __init__(self, *, selector, modifier):
        if not isinstance(selector, Selector) or not isinstance(modifier, Modifier):
            raise TypeError
        self._selector = selector
        self._modifier = modifier

    def apply(self, flatdoc):
        flatdoc = dot_flatdoc.as_flatdoc(flatdoc)

        old_idx = 0
        old_flatdoc = flatdoc[:]
        new_flatdoc = []
        for sl in self._selector.select(old_flatdoc):
            new_flatdoc.extend(old_flatdoc[old_idx : sl.start])
            new_flatdoc.extend(self._modifier.modify(old_flatdoc[sl]))
            old_idx = sl.stop
        new_flatdoc.extend(old_flatdoc[old_idx:])
        return new_flatdoc


def patch_from_dict(d):
    d = dict(d)

    selector = Selector(
        section=d.pop("section", None),
        kind=d.pop("kind", None),
        start=d.pop("start", None),
        stop=d.pop("stop", None),
    )

    op = d.pop("op", None)
    if op == "join":
        modifier = JoinModifier(sep=d.pop("sep", "\n\n"))
    elif op == "split":
        modifier = SplitModifier(sep=d.pop("sep", "\n\n"))
    else:
        raise ValueError

    if len(d) > 0:
        raise ValueError
    return Patch(selector=selector, modifier=modifier)


def as_patch(v):
    if isinstance(v, Patch):
        return v
    if isinstance(v, dict):
        return patch_from_dict(v)
    raise TypeError


def apply_patch_list(flatdoc, patch_list):
    flatdoc = dot_flatdoc.as_flatdoc(flatdoc)
    patch_list = list(map(as_patch, patch_list))

    flatdoc = flatdoc[:]
    for patch in patch_list:
        flatdoc = patch.apply(flatdoc)
    return flatdoc
