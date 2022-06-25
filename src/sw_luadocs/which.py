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


def ahk(*, mode=os.F_OK | os.X_OK):
    return which(
        filter(
            lambda exe: exe is not None,
            [
                os.environ.get("AHK_PATH"),
                shutil.which("AutoHotkey"),
                shutil.which("AutoHotkeyU64"),
                shutil.which("AutoHotkeyU32"),
                shutil.which("AutoHotkeyA32"),
                envpath("PROGRAMFILES", "AutoHotkey", "AutoHotkey.exe"),
                envpath("PROGRAMFILES", "AutoHotkey", "AutoHotkeyU64.exe"),
                envpath("PROGRAMFILES", "AutoHotkey", "AutoHotkeyU32.exe"),
                envpath("PROGRAMFILES", "AutoHotkey", "AutoHotkeyA32.exe"),
                envpath("PROGRAMFILES(X86)", "AutoHotkey", "AutoHotkey.exe"),
                envpath("PROGRAMFILES(X86)", "AutoHotkey", "AutoHotkeyU64.exe"),
                envpath("PROGRAMFILES(X86)", "AutoHotkey", "AutoHotkeyU32.exe"),
                envpath("PROGRAMFILES(X86)", "AutoHotkey", "AutoHotkeyA32.exe"),
            ],
        ),
        mode=mode,
    )


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
                shutil.which("stormworks"),
                envpath(
                    "PROGRAMFILES",
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
                    "stormworks64.exe",
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
