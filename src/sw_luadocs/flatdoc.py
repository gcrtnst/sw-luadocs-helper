import contextlib
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


class MdlikeParser:
    _linesep = "\n"
    _headseq = "# "
    _codeseq = "```"

    def __init__(self, s):
        s = str(s)
        line_list = s.split(self._linesep)

        self._line_list = line_list
        self._line_idx = 0

    def check_eof(self):
        return self._line_idx >= len(self._line_list)

    def peek(self, *, required=True):
        if self.check_eof():
            if required:
                raise ValueError
            return None
        return self._line_list[self._line_idx]

    def next(self):
        if not self.check_eof():
            self._line_idx += 1

    def pop(self, *, required=True):
        line = self.peek(required=required)
        self.next()
        return line

    @contextlib.contextmanager
    def transaction(self):
        line_idx = self._line_idx
        try:
            yield
        except:
            self._line_idx = line_idx
            raise

    def check_blank(self):
        line = self.peek(required=False)
        return line == ""

    def check_head(self):
        line = self.peek(required=False)
        return line is not None and line.startswith(self._headseq)

    def check_code(self):
        line = self.peek(required=False)
        return line == self._codeseq

    def check_body(self):
        return (
            not self.check_eof()
            and not self.check_blank()
            and not self.check_head()
            and not self.check_code()
        )

    def skip_blank(self):
        with self.transaction():
            while self.check_blank():
                self.next()

    def parse_head(self):
        if not self.check_head():
            raise ValueError

        with self.transaction():
            line = self.pop()
            txt = line[len(self._headseq) :]
            return FlatElem(txt=txt, kind="head")

    def parse_body(self):
        if not self.check_body():
            raise ValueError

        with self.transaction():
            line_list = []
            while self.check_body():
                line = self.pop()
                line_list.append(line)

            for i in range(len(line_list)):
                if line_list[i][-1] == "\\":
                    line_list[i] = line_list[i][:-1]

            txt = self._linesep.join(line_list)
            return FlatElem(txt=txt, kind="body")

    def parse_code(self):
        if not self.check_code():
            raise ValueError

        with self.transaction():
            self.next()

            line_list = []
            while True:
                line = self.pop()
                if line == self._codeseq:
                    break
                line_list.append(line)

            txt = self._linesep.join(line_list)
            return FlatElem(txt=txt, kind="code")

    def parse_elem(self):
        if self.check_head():
            return self.parse_head()
        if self.check_body():
            return self.parse_body()
        if self.check_code():
            return self.parse_code()
        raise ValueError

    def parse(self):
        with self.transaction():
            flatdoc = []
            while True:
                self.skip_blank()
                if self.check_eof():
                    return flatdoc
                flatelem = self.parse_elem()
                flatdoc.append(flatelem)


def parse_mdlike(s):
    p = MdlikeParser(s)
    return p.parse()


def format_mdlike(flatdoc):
    flatdoc = as_flatdoc(flatdoc)

    block_list = []
    for flatelem in flatdoc:
        if flatelem.kind == "head":
            block_list.append("# " + flatelem.txt + "\n")
            continue
        if flatelem.kind == "body":
            block_list.append(flatelem.txt.replace("\n", "\\\n") + "\\\n")
            continue
        if flatelem.kind == "code":
            block_list.append("```\n" + flatelem.txt + "\n```\n")
            continue
        raise RuntimeError
    s = "\n".join(block_list)

    if parse_mdlike(s) != flatdoc:
        raise ValueError
    return s


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
