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


def generate_repack_elem_patterns(ocr_txt_list, *, sep="\n\n"):
    ocr_txt_list = list(map(str, ocr_txt_list))
    sep = str(sep)

    if len(ocr_txt_list) <= 0:
        return []

    pak_txt_tuple_set = set()
    for pattern in range(1 << (len(ocr_txt_list) - 1)):
        pak_txt_list = []
        start_idx = 0
        for idx in range(1, len(ocr_txt_list)):
            if pattern & (1 << (idx - 1)) == 0:
                pak_txt = sep.join(ocr_txt_list[start_idx:idx])
                pak_txt_list.append(pak_txt)
                start_idx = idx
        pak_txt = sep.join(ocr_txt_list[start_idx:])
        pak_txt_list.append(pak_txt)

        pak_txt_tuple = tuple(pak_txt_list)
        pak_txt_tuple_set.add(pak_txt_tuple)

    pak_txt_list_list = sorted(map(list, pak_txt_tuple_set))
    return pak_txt_list_list


def generate_repack_line_patterns(ocr_txt_full):
    ocr_txt_full = str(ocr_txt_full)
    sep = "\n"

    ocr_txt_list = ocr_txt_full.split(sep=sep)
    old_txt_list_list = generate_repack_elem_patterns(ocr_txt_list, sep=sep)
    new_txt_list_list = list(
        filter(
            lambda old_txt_list: all(
                map(lambda old_txt: old_txt.replace("\n", "") != "", old_txt_list)
            ),
            old_txt_list_list,
        )
    )
    return new_txt_list_list


def match_txt_single(ocr_txt, ext_txt_set):
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


def match_txt_multiple(ocr_txt_list, ext_txt_set):
    ocr_txt_list = list(map(str, ocr_txt_list))
    ext_txt_set = set(map(str, ext_txt_set))

    best_ext_txt_list = []
    best_ld_sum = 0
    for ocr_txt in ocr_txt_list:
        best_ext_txt, best_ld = match_txt_single(ocr_txt, ext_txt_set)
        best_ext_txt_list.append(best_ext_txt)
        best_ld_sum += best_ld
    return best_ext_txt_list, best_ld_sum


def match_txt_repack(pak_txt_list_list, ext_txt_set):
    pak_txt_list_list = list(
        map(lambda pak_txt_list: list(map(str, pak_txt_list)), pak_txt_list_list)
    )
    ext_txt_set = set(map(str, ext_txt_set))

    best_ext_txt_list = None
    best_ld = None
    for pak_txt_list in pak_txt_list_list:
        ext_txt_list, ld = match_txt_multiple(pak_txt_list, ext_txt_set)
        if best_ld is None or ld < best_ld:
            best_ext_txt_list = ext_txt_list
            best_ld = ld

    if best_ext_txt_list is None or best_ld is None:
        return [], 0
    return best_ext_txt_list, best_ld


def match_flatelem(ocr_flatelem, ext_txt_set):
    if not isinstance(ocr_flatelem, dot_flatdoc.FlatElem):
        raise TypeError

    ocr_txt = ocr_flatelem.txt
    ext_txt, ld = match_txt_single(ocr_txt, ext_txt_set)
    ext_flatelem = dataclasses.replace(ocr_flatelem, txt=ext_txt)
    return ext_flatelem, ld


def match_flatdoc_each(ocr_flatdoc, ext_txt_set):
    ocr_flatdoc = dot_flatdoc.as_flatdoc(ocr_flatdoc)
    ext_txt_set = set(map(str, ext_txt_set))

    ext_flatdoc = []
    ld_sum = 0
    for ocr_flatelem in ocr_flatdoc:
        ext_flatelem, ld = match_flatelem(ocr_flatelem, ext_txt_set)
        ext_flatdoc.append(ext_flatelem)
        ld_sum += ld
    return ext_flatdoc, ld_sum


def match_flatdoc_repack_elem(ocr_flatdoc, ext_txt_set, *, sep="\n\n"):
    ocr_flatdoc = dot_flatdoc.as_flatdoc_monokind(ocr_flatdoc)

    kind = ocr_flatdoc[0].kind if len(ocr_flatdoc) > 0 else None
    ocr_txt_list = [ocr_flatelem.txt for ocr_flatelem in ocr_flatdoc]
    pak_txt_list_list = generate_repack_elem_patterns(ocr_txt_list, sep=sep)
    ext_txt_list, ld = match_txt_repack(pak_txt_list_list, ext_txt_set)
    ext_flatdoc = [
        dot_flatdoc.FlatElem(txt=ext_txt, kind=kind) for ext_txt in ext_txt_list
    ]
    return ext_flatdoc, ld


def match_flatdoc_monokind(
    ocr_flatdoc, ext_txt_set, *, body_sep="\n\n", code_sep="\n\n"
):
    ocr_flatdoc = dot_flatdoc.as_flatdoc_monokind(ocr_flatdoc)

    if len(ocr_flatdoc) <= 0:
        return [], 0
    if ocr_flatdoc[0].kind == "head":
        return match_flatdoc_each(ocr_flatdoc, ext_txt_set)
    if ocr_flatdoc[0].kind == "body":
        return match_flatdoc_repack_elem(ocr_flatdoc, ext_txt_set, sep=body_sep)
    if ocr_flatdoc[0].kind == "code":
        return match_flatdoc_repack_elem(ocr_flatdoc, ext_txt_set, sep=code_sep)
    raise RuntimeError


def match_flatdoc(ocr_flatdoc, ext_txt_set, *, body_sep="\n\n", code_sep="\n\n"):
    ext_txt_set = set(map(str, ext_txt_set))
    body_sep = str(body_sep)
    code_sep = str(code_sep)

    ext_flatdoc = []
    ld_sum = 0
    for ocr_flatdoc_monokind in dot_flatdoc.split_flatdoc_by_kind(ocr_flatdoc):
        ext_flatdoc_monokind, ld = match_flatdoc_monokind(
            ocr_flatdoc_monokind, ext_txt_set, body_sep=body_sep, code_sep=code_sep
        )
        ext_flatdoc.extend(ext_flatdoc_monokind)
        ld_sum += ld
    return ext_flatdoc, ld_sum


def extract(ocr_flatdoc, exe_bin, *, section_name, body_sep, code_sep):
    section_bin = extract_section(exe_bin, section_name, ignore_padding=True)
    ext_txt_set = extract_strings(section_bin)
    ext_flatdoc, _ = match_flatdoc(
        ocr_flatdoc, ext_txt_set, body_sep=body_sep, code_sep=code_sep
    )
    return ext_flatdoc
