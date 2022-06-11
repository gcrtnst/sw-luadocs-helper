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


def calc_levenshtein_distance(s, t):
    s = str(s)
    t = str(t)
    pad_s = " " + s
    pad_t = " " + t

    ld = [[0] * (len(pad_t)) for i in range(len(pad_s))]
    for i in range(1, len(pad_s)):
        ld[i][0] = i
    for j in range(1, len(pad_t)):
        ld[0][j] = j
    for i in range(1, len(pad_s)):
        for j in range(1, len(pad_t)):
            if pad_s[i] == pad_t[j]:
                ld[i][j] = ld[i - 1][j - 1]
                continue
            ld[i][j] = min(ld[i - 1][j - 1], ld[i - 1][j], ld[i][j - 1]) + 1
    return ld[-1][-1]
