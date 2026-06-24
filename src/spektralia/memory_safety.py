from __future__ import annotations

import ctypes
import mmap
import platform
import sys


_PR_SET_DUMPABLE = 4


def disable_core_dumps() -> None:
    """Refuse core dumps for this process (Linux only). No-op elsewhere."""
    if platform.system() == "Linux":
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
        except OSError:
            pass


class Secret:
    """Wraps a sensitive byte value in a zeroing bytearray.

    - __repr__ and __str__ never reveal the value.
    - wipe() overwrites with zeros immediately.
    - __del__ calls wipe() automatically.
    - Optional mlock() prevents the buffer from being swapped to disk.
    """

    __slots__ = ("_buf", "_label", "_locked")

    def __init__(self, value: bytes | bytearray, label: str = "SECRET") -> None:
        self._buf = bytearray(value)
        self._label = label
        self._locked = False

    def mlock(self) -> None:
        """Pin buffer in RAM (requires sufficient RLIMIT_MEMLOCK)."""
        if self._locked or not self._buf:
            return
        if platform.system() == "Linux":
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                addr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
                ret = libc.mlock(addr, len(self._buf))
                if ret == 0:
                    self._locked = True
            except OSError:
                pass

    def wipe(self) -> None:
        if self._buf:
            for i in range(len(self._buf)):
                self._buf[i] = 0
        if self._locked and platform.system() == "Linux":
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                addr = (ctypes.c_char * len(self._buf)).from_buffer(self._buf)
                libc.munlock(addr, len(self._buf))
            except OSError:
                pass
            self._locked = False

    def as_bytes(self) -> bytes:
        return bytes(self._buf)

    def as_str(self, encoding: str = "utf-8") -> str:
        return self._buf.decode(encoding)

    def __len__(self) -> int:
        return len(self._buf)

    def __repr__(self) -> str:
        return f"<Secret:{self._label}:redacted>"

    def __str__(self) -> str:
        return f"<Secret:{self._label}:redacted>"

    def __del__(self) -> None:
        self.wipe()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._buf == other._buf
        return NotImplemented

    def __hash__(self):
        raise TypeError("Secret is not hashable")


# Called at import time so that any code path importing this module
# (scanner, cli, etc.) sets PR_SET_DUMPABLE=0 immediately.
disable_core_dumps()
