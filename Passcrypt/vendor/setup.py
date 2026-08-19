"""
cryptogram - AES-NI accelerated Telegram MTProto crypto
Automatically enables hardware AES-NI when the CPU supports it.
"""
import os
import sys
from setuptools import setup, Extension

is_msvc = sys.platform == "win32" and "MSC" in sys.version

if is_msvc:
    extra_compile_args = ["/O2", "/W3"]
    aesni_flags = ["/arch:SSE2"]
else:
    extra_compile_args = [
        "-O3",
        "-funroll-loops",
        "-fomit-frame-pointer",
        "-std=c11",
        "-Wall",
        "-Wno-unused-variable",
    ]
    # -march=native is unsafe on macOS: universal2 fat binaries pass both
    # -arch arm64 and -arch x86_64, and clang rejects -march=native when
    # compiling the non-native slice.
    if sys.platform != "darwin":
        extra_compile_args.insert(1, "-march=native")

    # -maes/-msse2/-msse4.1 are x86-only and rejected by Apple clang on macOS.
    import platform
    machine = platform.machine().lower()
    is_x86 = machine in ("x86_64", "amd64", "i686", "i386")
    aesni_flags = [] if (sys.platform == "darwin" or not is_x86) else ["-maes", "-msse2", "-msse4.1"]

ext = Extension(
    "cryptogram._cryptogram",
    sources=["cryptogram/_cryptogram.c"],
    extra_compile_args=extra_compile_args + aesni_flags,
)

setup(ext_modules=[ext])
