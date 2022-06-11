import pefile


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


def extract_rdata(exe_bin, *, start=None, length=None, ignore_padding=False):
    if not isinstance(exe_bin, bytes):
        raise TypeError

    with pefile.PE(data=exe_bin, fast_load=False) as pe:
        for section in pe.sections:
            if section.Name == b".rdata\x00\x00":
                return section.get_data(
                    start=start, length=length, ignore_padding=ignore_padding
                )
    raise ValueError
