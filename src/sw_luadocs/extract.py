import dataclasses
import Levenshtein
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


def match_txt(ocr_txt, ext_txt_set):
    ocr_txt = str(ocr_txt)
    ext_txt_set = set(map(str, ext_txt_set))

    best_ext_txt = None
    best_ld = None
    ext_txt_list = sorted(ext_txt_set)
    for ext_txt in ext_txt_list:
        ld = Levenshtein.distance(ocr_txt, ext_txt)
        if best_ld is None or ld < best_ld:
            best_ext_txt = ext_txt
            best_ld = ld

    if best_ext_txt is None or best_ld is None:
        raise ValueError
    return best_ext_txt, best_ld


def match_flatelem(ocr_flatelem, ext_txt_set):
    if not isinstance(ocr_flatelem, dot_flatdoc.FlatElem):
        raise TypeError

    ocr_txt = ocr_flatelem.txt
    ext_txt, ld = match_txt(ocr_txt, ext_txt_set)
    ext_flatelem = dataclasses.replace(ocr_flatelem, txt=ext_txt)
    return ext_flatelem, ld


def match_flatdoc(ocr_flatdoc, ext_txt_set):
    ocr_flatdoc = dot_flatdoc.as_flatdoc(ocr_flatdoc)
    ext_txt_set = set(map(str, ext_txt_set))

    ext_flatdoc = []
    ld_sum = 0
    for ocr_flatelem in ocr_flatdoc:
        ext_flatelem, ld = match_flatelem(ocr_flatelem, ext_txt_set)
        ext_flatdoc.append(ext_flatelem)
        ld_sum += ld
    return ext_flatdoc, ld_sum


def extract(ocr_flatdoc, exe_bin, *, section_name):
    section_bin = extract_section(exe_bin, section_name, ignore_padding=True)
    ext_txt_set = extract_strings(section_bin)
    ext_flatdoc, _ = match_flatdoc(ocr_flatdoc, ext_txt_set)
    return ext_flatdoc
