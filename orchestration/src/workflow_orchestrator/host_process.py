"""Windows foreground-process observations; failed OS reads are never exits."""
from __future__ import annotations

import ctypes
import os
from typing import Any


def observe(pid: int, original: dict[str, Any] | None = None, *, handle: Any = None) -> dict[str, Any]:
    if os.name != 'nt':
        return {'state': 'unknown', 'reason': 'unsupported_platform'}
    from ctypes import wintypes as w
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    kernel.OpenProcess.restype = w.HANDLE
    kernel.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(ctypes.c_uint64)] * 4
    kernel.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
    kernel.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    owned = handle is None
    current = kernel.OpenProcess(0x1000 | 0x100000, False, pid) if owned else handle
    if not current:
        error = ctypes.get_last_error()
        if error == 87 and original:
            return {'state': 'exited', 'reason': 'not_present', 'exit_code': None,
                    'exit_code_known': False, 'identity': original}
        return {'state': 'unknown', 'reason': 'open_process_failed', 'os_error': error}
    try:
        times = [ctypes.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(current, *[ctypes.byref(v) for v in times]):
            return {'state': 'unknown', 'reason': 'process_times_failed', 'os_error': ctypes.get_last_error()}
        identity = {'pid': pid, 'creation_filetime': times[0].value}
        if original is not None and identity != original:
            return {'state': 'exited', 'reason': 'pid_reused', 'identity': original,
                    'exit_code': None, 'exit_code_known': False}
        # Wait distinguishes the legitimate exit code STILL_ACTIVE (259) from liveness.
        wait = kernel.WaitForSingleObject(current, 0)
        if wait == 258:
            return {'state': 'running', 'identity': identity}
        if wait != 0:
            return {'state': 'unknown', 'reason': 'wait_failed', 'os_error': ctypes.get_last_error(), 'identity': identity}
        code = w.DWORD()
        known = bool(kernel.GetExitCodeProcess(current, ctypes.byref(code)))
        return {'state': 'exited', 'reason': 'signalled', 'identity': identity,
                'exit_code': code.value if known else None, 'exit_code_known': known}
    finally:
        if owned:
            kernel.CloseHandle(current)
