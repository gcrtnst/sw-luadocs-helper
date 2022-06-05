import contextlib
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
