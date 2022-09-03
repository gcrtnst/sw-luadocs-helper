import contextlib
import functools


from . import win32 as dot_win32


@contextlib.contextmanager
def manage_dpictx(dpictx):
    oldctx = None
    try:
        oldctx = dot_win32.SetThreadDpiAwarenessContext(dpictx)
        yield
    finally:
        if oldctx is not None:
            dot_win32.SetThreadDpiAwarenessContext(oldctx)


def _decorate(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        with manage_dpictx(dot_win32.DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2):
            return func(*args, **kwargs)

    return wrapper


ClientToScreen = _decorate(dot_win32.ClientToScreen)
GetClientRect = _decorate(dot_win32.GetClientRect)
GetSystemMetrics = _decorate(dot_win32.GetSystemMetrics)
SendInput = _decorate(dot_win32.SendInput)
SetCursorPos = _decorate(dot_win32.SetCursorPos)
