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


def calc_levenshtein_dp(s, t):
    s = str(s)
    t = str(t)
    pad_s = " " + s
    pad_t = " " + t

    lddp = [[0] * len(pad_t) for i in range(len(pad_s))]
    for i in range(1, len(pad_s)):
        lddp[i][0] = i
    for j in range(1, len(pad_t)):
        lddp[0][j] = j
    for i in range(1, len(pad_s)):
        for j in range(1, len(pad_t)):
            lddp[i][j] = min(
                lddp[i - 1][j - 1] + (0 if pad_s[i] == pad_t[j] else 1),
                lddp[i - 1][j] + 1,
                lddp[i][j - 1] + 1,
            )
    return lddp


def match_txt_repack_adv(ocr_txt_list, ext_txt, *, sep="\n"):
    ocr_txt_list = list(map(str, ocr_txt_list))
    ext_txt = str(ext_txt)
    sep = str(sep)

    ocr_txt_full = sep.join(ocr_txt_list)
    lddp = calc_levenshtein_dp(ocr_txt_full, ext_txt)

    adv_list = [None] * (len(ocr_txt_full) + 1)
    i = 0
    for adv, ocr_txt in enumerate(ocr_txt_list[:-1], start=1):
        i += len(ocr_txt)
        adv_list[i] = adv
        for j in range(len(sep)):
            i += 1
            adv_list[i] = adv
    adv_list[-1] = len(ocr_txt_list)

    best_adv = None
    best_ld = None
    for i in range(len(lddp)):
        adv = adv_list[i]
        ld = lddp[i][-1]
        if adv is not None and (best_ld is None or ld <= best_ld):
            best_adv = adv
            best_ld = ld
    return best_adv, best_ld


def match_txt_repack_left(ocr_txt_list, ext_txt_set, *, sep="\n"):
    ocr_txt_list = list(map(str, ocr_txt_list))
    ext_txt_set = set(map(str, ext_txt_set))
    sep = str(sep)

    ext_txt_list = sorted(ext_txt_set)

    best_ext_txt = None
    best_adv = None
    best_ld = None
    for ext_txt in ext_txt_list:
        adv, ld = match_txt_repack_adv(ocr_txt_list, ext_txt, sep=sep)
        if best_ld is None or (
            (ld, -adv, -len(ext_txt)) < (best_ld, -best_adv, -len(best_ext_txt))
        ):
            best_ext_txt = ext_txt
            best_adv = adv
            best_ld = ld
    if best_ext_txt is None or best_adv is None or best_ld is None:
        raise ValueError
    return best_ext_txt, best_adv, best_ld


def match_txt_repack(ocr_txt_list, ext_txt_set, *, sep="\n"):
    ocr_txt_list = list(map(str, ocr_txt_list))
    ext_txt_set = set(map(str, ext_txt_set))
    sep = str(sep)

    ext_txt_list = []
    ldsum = 0
    idx = 0
    while idx < len(ocr_txt_list):
        ext_txt, adv, ld = match_txt_repack_left(
            ocr_txt_list[idx:], ext_txt_set, sep=sep
        )
        ext_txt_list.append(ext_txt)
        idx += adv
        ldsum += ld
    return ext_txt_list, ldsum


def match_flatdoc_repack_line(ocr_flatdoc, ext_txt_set, *, sep="\n\n"):
    ocr_flatdoc = dot_flatdoc.as_flatdoc_monokind(ocr_flatdoc)
    sep = str(sep)

    if len(ocr_flatdoc) <= 0:
        return [], 0

    kind = ocr_flatdoc[0].kind if len(ocr_flatdoc) > 0 else None
    ocr_txt_full = sep.join(ocr_flatelem.txt for ocr_flatelem in ocr_flatdoc)
    ocr_txt_list = ocr_txt_full.split("\n")
    ext_txt_list, ld = match_txt_repack(ocr_txt_list, ext_txt_set, sep="\n")
    ext_flatdoc = [
        dot_flatdoc.FlatElem(txt=ext_txt, kind=kind) for ext_txt in ext_txt_list
    ]
    return ext_flatdoc, ld


def match_flatdoc(ocr_flatdoc, ext_txt_set, *, sep="\n\n"):
    ext_txt_set = set(map(str, ext_txt_set))
    sep = str(sep)

    ext_flatdoc = []
    ld_sum = 0
    for ocr_flatdoc_monokind in dot_flatdoc.split_flatdoc_by_kind(ocr_flatdoc):
        ext_flatdoc_monokind, ld = match_flatdoc_repack_line(
            ocr_flatdoc_monokind, ext_txt_set, sep=sep
        )
        ext_flatdoc.extend(ext_flatdoc_monokind)
        ld_sum += ld
    return ext_flatdoc, ld_sum


def extract(ocr_flatdoc, exe_bin, *, section_name, sep):
    section_bin = extract_section(exe_bin, section_name, ignore_padding=True)
    ext_txt_set = extract_strings(section_bin)
    ext_flatdoc, _ = match_flatdoc(ocr_flatdoc, ext_txt_set, sep=sep)
    return ext_flatdoc
