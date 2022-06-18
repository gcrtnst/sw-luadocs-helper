import Levenshtein
import pefile
import re


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


def generate_concat_patterns(ocr_txt_list, *, sep="\n"):
    ocr_txt_list = list(map(str, ocr_txt_list))
    sep = str(sep)

    if len(ocr_txt_list) <= 0:
        return set()

    cat_txt_tuple_set = set()
    for pattern in range(1 << (len(ocr_txt_list) - 1)):
        cat_txt_list = []
        start_idx = 0
        for idx in range(1, len(ocr_txt_list)):
            if pattern & (1 << (idx - 1)) == 0:
                cat_txt = sep.join(ocr_txt_list[start_idx:idx])
                cat_txt_list.append(cat_txt)
                start_idx = idx
        cat_txt = sep.join(ocr_txt_list[start_idx:])
        cat_txt_list.append(cat_txt)

        cat_txt_tuple = tuple(cat_txt_list)
        cat_txt_tuple_set.add(cat_txt_tuple)
    return cat_txt_tuple_set


def match_single(ocr_txt, ext_txt_set):
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


def match_multiple(ocr_txt_list, ext_txt_set):
    ocr_txt_list = list(map(str, ocr_txt_list))
    ext_txt_set = set(map(str, ext_txt_set))

    best_ext_txt_list = []
    best_ld_sum = 0
    for ocr_txt in ocr_txt_list:
        best_ext_txt, best_ld = match_single(ocr_txt, ext_txt_set)
        best_ext_txt_list.append(best_ext_txt)
        best_ld_sum += best_ld
    return best_ext_txt_list, best_ld_sum
