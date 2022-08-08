import ctypes
import ctypes.wintypes


GWL_EXSTYLE = -20
INPUT_HARDWARE = 2
INPUT_KEYBOARD = 1
INPUT_MOUSE = 0
MOUSEEVENTF_WHEEL = 2048
SM_CXSCREEN = 0
SM_CYSCREEN = 1
SW_MINIMIZE = 6
SW_RESTORE = 9
SW_SHOWMINIMIZED = 2
WS_EX_TOPMOST = 8


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.wintypes.LONG),
        ("dy", ctypes.wintypes.LONG),
        ("mouseData", ctypes.wintypes.DWORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("time", ctypes.wintypes.DWORD),
        ("dwExtraInfo", ctypes.wintypes.LPARAM),
    ]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.wintypes.WORD),
        ("wScan", ctypes.wintypes.WORD),
        ("dwFlags", ctypes.wintypes.DWORD),
        ("time", ctypes.wintypes.DWORD),
        ("dwExtraInfo", ctypes.wintypes.LPARAM),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", ctypes.wintypes.DWORD),
        ("wParamL", ctypes.wintypes.WORD),
        ("wParamH", ctypes.wintypes.WORD),
    ]


class _INPUT_U(ctypes.Union):
    _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]


class _INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", ctypes.wintypes.DWORD), ("u", _INPUT_U)]


class INPUT:
    _type = None
    _attr = None

    def __init__(self, *args, **kwargs):
        if self._type is None or self._attr is None:
            raise NotImplementedError

        _c = _INPUT()
        _i = getattr(_c, self._attr)
        _i_attrs = frozenset(field[0] for field in _i._fields_)
        _c.type = self._type
        setattr(_c, self._attr, type(_i)(*args, **kwargs))

        super().__setattr__("_c", _c)
        super().__setattr__("_i", _i)
        super().__setattr__("_i_attrs", _i_attrs)

    def __getattr__(self, name):
        if name in self._i_attrs:
            return getattr(self._i, name)
        raise AttributeError

    def __setattr__(self, name, value):
        if name in self._i_attrs:
            return setattr(self._i, name, value)
        return super().__setattr__(name, value)

    def __dir__(self):
        yield from self._i_attrs
        yield from super().__dir__()


class MOUSEINPUT(INPUT):
    _type = INPUT_MOUSE
    _attr = "mi"


class KEYBDINPUT(INPUT):
    _type = INPUT_KEYBOARD
    _attr = "ki"


class HARDWAREINPUT(INPUT):
    _type = INPUT_HARDWARE
    _attr = "hi"


def _create_input_array(input_list):
    input_list = list(input_list)
    for i in range(len(input_list)):
        if not isinstance(input_list[i], INPUT):
            raise TypeError

    _input_arr = (_INPUT * len(input_list))()
    for i in range(len(input_list)):
        _input_arr[i] = input_list[i]._c
    return _input_arr


def ClientToScreen(hWnd, Point):
    PointX, PointY = Point
    PointX = int(PointX)
    PointY = int(PointY)
    _Point = ctypes.wintypes.POINT(x=PointX, y=PointY)

    def errcheck(result, func, args):
        if result == 0:
            raise ctypes.WinError()

    fp = ctypes.windll.user32.ClientToScreen
    fp.argtypes = ctypes.wintypes.HWND, ctypes.wintypes.LPPOINT
    fp.restype = ctypes.wintypes.BOOL
    fp.errcheck = errcheck
    fp(hWnd, ctypes.byref(_Point))
    return _Point.x, _Point.y


def FindWindow(lpClassName, lpWindowName):
    def errcheck(result, func, args):
        if result is None:
            code = ctypes.GetLastError()
            if code != 0:
                raise ctypes.WinError(code=code)
        return result

    fp = ctypes.windll.user32.FindWindowW
    fp.argtypes = ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPCWSTR
    fp.restype = ctypes.wintypes.HWND
    fp.errcheck = errcheck

    SetLastError(0)
    return fp(lpClassName, lpWindowName)


def GetClientRect(hWnd):
    Rect = ctypes.wintypes.RECT()

    def errcheck(result, func, args):
        if result == 0:
            raise ctypes.WinError()

    fp = ctypes.windll.user32.GetClientRect
    fp.argtypes = ctypes.wintypes.HWND, ctypes.wintypes.LPRECT
    fp.restype = ctypes.wintypes.BOOL
    fp.errcheck = errcheck
    fp(hWnd, ctypes.byref(Rect))
    return Rect.left, Rect.top, Rect.right, Rect.bottom


def GetForegroundWindow():
    fp = ctypes.windll.user32.GetForegroundWindow
    fp.argtypes = ()
    fp.restype = ctypes.wintypes.HWND
    return fp()


def GetSystemMetrics(nIndex):
    fp = ctypes.windll.user32.GetSystemMetrics
    fp.argtypes = (ctypes.c_int,)
    fp.restype = ctypes.c_int
    return fp(nIndex)


def GetWindowLong(hWnd, nIndex):
    def errcheck(result, func, args):
        if result == 0:
            code = ctypes.GetLastError()
            if code != 0:
                raise ctypes.WinError(code=code)
        return result

    fp = ctypes.windll.user32.GetWindowLongPtrW
    fp.argtypes = ctypes.wintypes.HWND, ctypes.c_int
    fp.restype = ctypes.wintypes.LPARAM
    fp.errcheck = errcheck

    SetLastError(0)
    return fp(hWnd, nIndex)


def IsIconic(hWnd):
    fp = ctypes.windll.user32.IsIconic
    fp.argtypes = (ctypes.wintypes.HWND,)
    fp.restype = ctypes.wintypes.BOOL
    return fp(hWnd)


def mouse_event(dwFlags, dx, dy, dwData, dwExtraInfo):
    fp = ctypes.windll.user32.mouse_event
    fp.argtypes = (
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.c_void_p,
    )
    fp.restype = None
    return fp(dwFlags, dx, dy, dwData, dwExtraInfo)


def SendInput(pInputs):
    _pInputs = _create_input_array(pInputs)

    def errcheck(result, func, args):
        if result == 0:
            raise ctypes.WinError()
        return result

    fp = ctypes.windll.user32.SendInput
    fp.argtypes = ctypes.wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int
    fp.restype = ctypes.wintypes.UINT
    fp.errcheck = errcheck
    return fp(len(_pInputs), _pInputs, ctypes.sizeof(_INPUT))


def SetCursorPos(X, Y):
    def errcheck(result, func, args):
        if result == 0:
            raise ctypes.WinError()

    fp = ctypes.windll.user32.SetCursorPos
    fp.argtypes = ctypes.c_int, ctypes.c_int
    fp.restype = ctypes.wintypes.BOOL
    fp.errcheck = errcheck
    return fp(X, Y)


def SetLastError(dwErrCode):
    fp = ctypes.windll.kernel32.SetLastError
    fp.argtypes = (ctypes.wintypes.DWORD,)
    fp.restype = None
    return fp(dwErrCode)


def ShowWindow(hWnd, nCmdShow):
    fp = ctypes.windll.user32.ShowWindow
    fp.argtypes = ctypes.wintypes.HWND, ctypes.c_int
    fp.restype = ctypes.wintypes.BOOL
    return fp(hWnd, nCmdShow)
