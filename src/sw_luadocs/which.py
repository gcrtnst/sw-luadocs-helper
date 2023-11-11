import os
import shutil
import pathlib


def envpath(env_key, *path):
    env_val = os.environ.get(env_key)
    if env_val is None:
        return None
    return pathlib.Path(env_val, *path)


def which(exe_list, *, mode=os.F_OK | os.X_OK):
    for exe in exe_list:
        exe = pathlib.Path(exe)
        if os.access(exe, mode):
            return exe
    return None


def tesseract(*, mode=os.F_OK | os.X_OK):
    return which(
        filter(
            lambda exe: exe is not None,
            [
                shutil.which("tesseract"),
                envpath("PROGRAMFILES", "Tesseract-OCR", "tesseract.exe"),
                envpath("PROGRAMFILES(X86)", "Tesseract-OCR", "tesseract.exe"),
            ],
        ),
        mode=mode,
    )


def stormworks(*, mode=os.F_OK | os.X_OK):
    return which(
        filter(
            lambda exe: exe is not None,
            [
                envpath(
                    "PROGRAMFILES",
                    "Steam",
                    "steamapps",
                    "common",
                    "Stormworks",
                    "stormworks64.exe",
                ),
                envpath(
                    "PROGRAMFILES(X86)",
                    "Steam",
                    "steamapps",
                    "common",
                    "Stormworks",
                    "stormworks64.exe",
                ),
                envpath(
                    "PROGRAMFILES",
                    "Steam",
                    "steamapps",
                    "common",
                    "Stormworks",
                    "stormworks.exe",
                ),
                envpath(
                    "PROGRAMFILES(X86)",
                    "Steam",
                    "steamapps",
                    "common",
                    "Stormworks",
                    "stormworks.exe",
                ),
            ],
        ),
        mode=mode,
    )
