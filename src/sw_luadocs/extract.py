import pefile


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
