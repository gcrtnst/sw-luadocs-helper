import ctypes
import ctypes.wintypes


GWL_EXSTYLE = -20
MOUSEEVENTF_WHEEL = 2048
SM_CXSCREEN = 0
SM_CYSCREEN = 1
SW_MINIMIZE = 6
SW_RESTORE = 9
SW_SHOWMINIMIZED = 2
WS_EX_TOPMOST = 8


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
