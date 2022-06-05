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


def as_flatdoc(v):
    flatdoc = []
    for flatelem in v:
        if not isinstance(flatelem, FlatElem):
            raise TypeError
        flatdoc.append(flatelem)
    return flatdoc


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


def format_mdlike(flatdoc):
    flatdoc = as_flatdoc(flatdoc)

    block_list = []
    for flatelem in flatdoc:
        if flatelem.kind == "head":
            block_list.append("# " + flatelem.txt + "\n")
            continue
        if flatelem.kind == "body":
            block_list.append(flatelem.txt + "\n")
            continue
        if flatelem.kind == "code":
            block_list.append("```\n" + flatelem.txt + "\n```\n")
            continue
        raise RuntimeError
    s = "\n".join(block_list)

    if parse_mdlike(s) != flatdoc:
        raise ValueError
    return s
