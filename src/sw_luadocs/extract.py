import pefile
import re

from . import flatdoc as dot_flatdoc


def encode_section_name(section_name):
    section_name = str(section_name)

    section_name_bin = section_name.encode(encoding="utf-8", errors="strict")
    if (len(section_name_bin) >= 1 and section_name_bin[0] == b"/"[0]) or len(
        section_name_bin
    ) > 8:
        raise ValueError
    if len(section_name_bin) < 8:
        section_name_bin += bytes(8 - len(section_name_bin))
    return section_name_bin


def extract_section(
    exe_bin, section_name, *, start=None, length=None, ignore_padding=False
):
    if not isinstance(exe_bin, bytes):
        raise TypeError
    section_name_bin = encode_section_name(section_name)

    with pefile.PE(data=exe_bin, fast_load=True) as pe:
        for section in pe.sections:
            if section.Name == section_name_bin:
                return section.get_data(
                    start=start, length=length, ignore_padding=ignore_padding
                )
    raise ValueError


def extract_strings(section_bin):
    if not isinstance(section_bin, bytes):
        raise TypeError

    ext_txt_set = set()
    robj = re.compile(rb"[\x20-\x7E\t\r\n]+\x00", flags=re.ASCII)
    for ext_txt_bin in robj.findall(section_bin):
        ext_txt = ext_txt_bin[:-1].decode(encoding="ascii", errors="strict")
        ext_txt_set.add(ext_txt)
    return ext_txt_set


class Ngram:
    def __init__(self, txt, *, n=2):
        n = int(n)
        if n <= 0:
            raise ValueError

        txt = str(txt)
        bag = frozenset()
        if txt != "":
            pad = "\0" * (n - 1) + txt + "\0" * (n - 1)
            bag = frozenset(pad[i : i + n] for i in range(len(pad) - n + 1))

        self._n = n
        self._txt = txt
        self._bag = bag

    n = property(lambda self: self._n)
    txt = property(lambda self: self._txt)
    bag = property(lambda self: self._bag)

    def __repr__(self):
        return f"{type(self).__name__}({repr(self.txt)}, n={repr(self.n)})"

    def __eq__(self, other):
        if type(self) is not type(other):
            return NotImplemented
        return self.n == other.n and self.txt == other.txt

    def __hash__(self):
        return hash((self.n, self.txt))


def calc_jaccard_similarity(ngram1, ngram2):
    if not isinstance(ngram1, Ngram) or not isinstance(ngram2, Ngram):
        raise TypeError
    if ngram1.n != ngram2.n:
        raise ValueError
    if len(ngram1.bag) <= 0 and len(ngram2.bag) <= 0:
        return 1.0
    return len(ngram1.bag & ngram2.bag) / len(ngram1.bag | ngram2.bag)


def calc_length_similarity(len1, len2):
    len1 = int(len1)
    len2 = int(len2)

    if len1 < 0 or len2 < 0:
        raise ValueError
    if len1 == 0 and len2 == 0:
        return 1.0
    return min(len1, len2) / max(len1, len2)


def calc_score(ngram1, ngram2):
    if not isinstance(ngram1, Ngram) or not isinstance(ngram2, Ngram):
        raise TypeError

    jac_score = calc_jaccard_similarity(ngram1, ngram2)
    len_score = calc_length_similarity(len(ngram1.txt), len(ngram2.txt))
    return jac_score * len_score


class NgramDatabase:
    def __init__(self, txt_set, *, n=2):
        n = int(n)
        if n <= 0:
            raise ValueError

        txt_set = frozenset(map(str, txt_set))
        db = frozenset(Ngram(txt, n=n) for txt in txt_set)

        self._n = n
        self._db = db

    n = property(lambda self: self._n)
    db = property(lambda self: (ngram for ngram in self._db))


def match_txt_single(ocr_txt, ext_txt_db):
    ocr_txt = str(ocr_txt)
    if not isinstance(ext_txt_db, NgramDatabase):
        raise TypeError

    ocr_ngram = Ngram(ocr_txt, n=ext_txt_db.n)
    best_ext_txt = None
    best_score = None
    for ext_ngram in ext_txt_db.db:
        score = calc_score(ocr_ngram, ext_ngram)
        if (
            best_score is None
            or best_score < score
            or (best_score == score and ext_ngram.txt < best_ext_txt)
        ):
            best_ext_txt = ext_ngram.txt
            best_score = score
    if best_ext_txt is None or best_score is None:
        raise ValueError
    return best_ext_txt, best_score


def match_txt_left(ocr_txt_list, ext_txt_db, *, sep="\n"):
    ocr_txt_list = list(map(str, ocr_txt_list))
    sep = str(sep)
    if not isinstance(ext_txt_db, NgramDatabase):
        raise TypeError

    best_ext_txt = None
    best_adv = None
    best_score = None
    for adv in range(1, len(ocr_txt_list) + 1):
        ocr_txt = sep.join(ocr_txt_list[:adv])
        ext_txt, score = match_txt_single(ocr_txt, ext_txt_db)
        if best_score is None or best_score < score:
            best_ext_txt = ext_txt
            best_adv = adv
            best_score = score
    if best_ext_txt is None or best_adv is None:
        raise ValueError
    return best_ext_txt, best_adv, best_score


def match_txt_pack(ocr_txt_list, ext_txt_db, *, sep="\n"):
    ocr_txt_list = list(map(str, ocr_txt_list))
    sep = str(sep)
    if not isinstance(ext_txt_db, NgramDatabase):
        raise TypeError

    ext_txt_list = []
    min_score = 1.0
    idx = 0
    while idx < len(ocr_txt_list):
        ext_txt, adv, score = match_txt_left(ocr_txt_list[idx:], ext_txt_db, sep=sep)
        ext_txt_list.append(ext_txt)
        min_score = min(min_score, score)
        idx += adv
    return ext_txt_list, min_score


def match_flatdoc_eachelem(ocr_flatdoc, ext_txt_db):
    ocr_flatdoc = dot_flatdoc.as_flatdoc(ocr_flatdoc)
    if not isinstance(ext_txt_db, NgramDatabase):
        raise TypeError

    ext_flatdoc = []
    min_score = 1.0
    for ocr_flatelem in ocr_flatdoc:
        kind = ocr_flatelem.kind
        ocr_txt = ocr_flatelem.txt
        ext_txt, score = match_txt_single(ocr_txt, ext_txt_db)
        ext_flatelem = dot_flatdoc.FlatElem(txt=ext_txt, kind=kind)
        ext_flatdoc.append(ext_flatelem)
        min_score = min(min_score, score)
    return ext_flatdoc, min_score


def match_flatdoc_packelem(ocr_flatdoc, ext_txt_db, *, sep="\n\n"):
    ocr_flatdoc = dot_flatdoc.as_flatdoc_monokind(ocr_flatdoc)

    kind = ocr_flatdoc[0].kind if len(ocr_flatdoc) > 0 else None
    ocr_txt_list = [ocr_flatelem.txt for ocr_flatelem in ocr_flatdoc]
    ext_txt_list, score = match_txt_pack(ocr_txt_list, ext_txt_db, sep=sep)
    ext_flatdoc = [
        dot_flatdoc.FlatElem(txt=ext_txt, kind=kind) for ext_txt in ext_txt_list
    ]
    return ext_flatdoc, score


def match_flatdoc_packline(ocr_flatdoc, ext_txt_db, *, sep="\n\n"):
    ocr_flatdoc = dot_flatdoc.as_flatdoc_monokind(ocr_flatdoc)
    sep = str(sep)
    if not isinstance(ext_txt_db, NgramDatabase):
        raise TypeError

    if len(ocr_flatdoc) <= 0:
        return [], 1.0

    kind = ocr_flatdoc[0].kind
    ocr_txt_full = sep.join(ocr_flatelem.txt for ocr_flatelem in ocr_flatdoc)
    ocr_txt_list = ocr_txt_full.split("\n")
    ext_txt_list, score = match_txt_pack(ocr_txt_list, ext_txt_db, sep="\n")
    ext_flatdoc = [
        dot_flatdoc.FlatElem(txt=ext_txt, kind=kind) for ext_txt in ext_txt_list
    ]
    return ext_flatdoc, score


def match_flatdoc(ocr_flatdoc, ext_txt_db, *, sep="\n\n"):
    ocr_flatdoc = dot_flatdoc.as_flatdoc(ocr_flatdoc)
    sep = str(sep)
    if not isinstance(ext_txt_db, NgramDatabase):
        raise TypeError

    ext_flatdoc = []
    min_score = 1.0
    for ocr_flatdoc_monokind in dot_flatdoc.split_flatdoc_by_kind(ocr_flatdoc):
        ext_flatdoc_monokind, score = match_flatdoc_packline(
            ocr_flatdoc_monokind, ext_txt_db, sep=sep
        )
        ext_flatdoc.extend(ext_flatdoc_monokind)
        min_score = min(min_score, score)
    return ext_flatdoc, min_score


def extract(ocr_flatdoc, exe_bin, *, section_name, ngram, sep):
    section_bin = extract_section(exe_bin, section_name, ignore_padding=True)
    ext_txt_set = extract_strings(section_bin)
    ext_txt_db = NgramDatabase(ext_txt_set, n=ngram)
    ext_flatdoc, _ = match_flatdoc(ocr_flatdoc, ext_txt_db, sep=sep)
    return ext_flatdoc
