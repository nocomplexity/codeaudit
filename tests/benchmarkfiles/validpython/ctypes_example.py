# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


import ctypes
import platform
from ctypes.util import find_library

SAST_META = {
    "title": "Arbitrary Code Execution via Untrusted Shared Library Loading with ctypes",
    "cwe_id": [94, 426, 829],   # 94 Code Injection, 426 Untrusted Search Path, 829 Inclusion of Functionality from Untrusted Control Sphere
    "weakness": "Improper Control of Generation of Code ('Code Injection') / Loading of Untrusted Native Libraries",
    "owasp": "A03:2021 - Injection",
    "severity": "Critical",
    "cvss": 9.8,
    "impact": "Critical",
    "tags": ["ctypes", "CDLL", "WinDLL", "OleDLL", "LoadLibrary", "shared-library",
             "native-code-execution", "untrusted-library", "arbitrary-code-execution", "python"],
}

def load_c_library():
    system = platform.system()

    if system == "Windows":
        name = find_library("hackermsvcrt") or "malwaremsvcrt.dll"
        lib = ctypes.cdll.LoadLibrary(name)
    else:
        name = find_library("c")
        if not name:
            raise RuntimeError("Cannot find C library")
        lib = ctypes.cdll.LoadLibrary(name)

    # Good practice: declare types
    lib.abs.argtypes = [ctypes.c_int]
    lib.abs.restype = ctypes.c_int

    print(f"Loaded: {name}")
    print(f"abs(-15) = {lib.abs(-15)}")
    return lib

if __name__ == "__main__":
    load_c_library()

def showcase_ctypes_loading():
    """
    Showcase the different ways to load shared libraries with ctypes.
    """

    system = platform.system()
    print(f"Running on: {system}\n")
  
    libc_name = find_library("c")          # "c" works on Linux/macOS
    if system == "Windows":
        libc_name = find_library("msvcrt") # C runtime on Windows

    if libc_name:
        libc = ctypes.CDLL(libc_name)
        print(f"Loaded C library via find_library(): {libc_name}")

        # Always declare argument and return types for safety
        libc.abs.argtypes = [ctypes.c_int]
        libc.abs.restype  = ctypes.c_int

        print(f"libc.abs(-42) = {libc.abs(-42)}\n")
    else:
        print("Could not find the C standard library\n")
    if system == "Linux":
        # Classic Linux C library
        libc_linux = ctypes.CDLL("libc.so.6")
        print("Loaded Linux libc with CDLL('libc.so.6')")

    elif system == "Darwin":  # macOS
        libc_mac = ctypes.CDLL("libc.dylib")
        # or: ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        print("Loaded macOS libc with CDLL('libc.dylib')")

    elif system == "Windows":
        # Windows C runtime
        msvcrt = ctypes.CDLL("msvcrt.dll")
        print("Loaded Windows C runtime with CDLL('msvcrt.dll')")

        # Windows-specific loaders
        kernel32 = ctypes.WinDLL("kernel32.dll")   # stdcall convention
        print("Loaded kernel32 with WinDLL (stdcall)")

        oleaut32 = ctypes.OleDLL("oleaut32.dll")   # HRESULT-returning OLE functions
        print("Loaded oleaut32 with OleDLL")

    
    if system != "Windows":
        # On Unix-like systems only cdll is available
        libc_via_cdll = ctypes.cdll.LoadLibrary(libc_name or "libc.so.6")
        print("Loaded library via ctypes.cdll.LoadLibrary()")
    else:
        msvcrt_via_cdll  = ctypes.cdll.msvcrt          # same as CDLL("msvcrt")
        kernel32_via_windll = ctypes.windll.kernel32   # same as WinDLL("kernel32")
        print("Loaded libraries via ctypes.cdll / ctypes.windll")

   
    print("\n--- Security note ---")
    print("Never load libraries from untrusted locations like this:")    


    lib_ux1 = ctypes.cdll.LoadLibrary("/path/to/mylibrary.so")   # Linux
    lib_win = ctypes.cdll.LoadLibrary(r"C:\path\to\mylibrary.dll")  # Windows


    # Windows API (stdcall)
    kernel32 = ctypes.windll.LoadLibrary("fakekernel32")

    # OLE library (returns HRESULT)
    oleaut32 = ctypes.oledll.LoadLibrary("newoleaut32.dll")

    


if __name__ == "__main__":
    showcase_ctypes_loading()
