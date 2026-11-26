"""Windows CurrentUser DPAPI storage. This does not isolate same-user processes.

Only ciphertext reaches disk. Python strings cannot be reliably memory-erased;
DPAPI buffers are cleared before release. No network, credential discovery or ACL
changes occur. A failed write can leave an unusable ciphertext file, never a
plaintext temporary file; existing files are never overwritten or deleted.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import re

_PROJECT_ROOT = Path(__file__).absolute().parents[2]
_MAGIC = b"TGAG-DPAPI\x00\x01"
_MAX_BLOB = 16384
_TOKEN = re.compile(r"[1-9][0-9]{0,15}:[A-Za-z0-9_-]{35}\Z")


class TokenStoreError(ValueError):
    """Intentionally excludes paths, tokens and underlying Windows errors."""


def _fail():
    raise TokenStoreError("Token storage is unavailable") from None


def validate_token(token: str) -> str:
    if type(token) is not str or not _TOKEN.fullmatch(token):
        _fail()
    if int(token.partition(":")[0]) > 2**52 - 1:
        _fail()
    return token


class _Blob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt(data: bytes, *, decrypt: bool) -> bytes:
    if os.name != "nt":
        _fail()
    source = ctypes.create_string_buffer(data, len(data))
    incoming = _Blob(len(data), ctypes.cast(source, ctypes.POINTER(ctypes.c_ubyte)))
    outgoing = _Blob()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    crypt = ctypes.WinDLL("crypt32", use_last_error=True)
    operation = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    operation.argtypes = [ctypes.POINTER(_Blob), ctypes.c_void_p, ctypes.c_void_p,
                          ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
                          ctypes.POINTER(_Blob)]
    operation.restype = wintypes.BOOL
    try:
        # CRYPTPROTECT_UI_FORBIDDEN only. No LOCAL_MACHINE flag, entropy, UI,
        # description or roaming/account setup: CurrentUser is the default.
        if not operation(ctypes.byref(incoming), None, None, None, None, 0x1,
                         ctypes.byref(outgoing)):
            _fail()
        if not outgoing.data or not 0 < outgoing.size <= _MAX_BLOB:
            _fail()
        return ctypes.string_at(outgoing.data, outgoing.size)
    finally:
        ctypes.memset(source, 0, len(data))
        if outgoing.data:
            ctypes.memset(outgoing.data, 0, outgoing.size)
            kernel.LocalFree(outgoing.data)


def protect_token(token: str) -> bytes:
    try:
        payload = _crypt(validate_token(token).encode("ascii"), decrypt=False)
        if type(payload) is not bytes or not 0 < len(payload) <= _MAX_BLOB - len(_MAGIC):
            _fail()
        return _MAGIC + payload
    except Exception:
        _fail()


def unprotect_token(blob: bytes) -> str:
    try:
        if type(blob) is not bytes or not len(_MAGIC) < len(blob) <= _MAX_BLOB:
            _fail()
        if not blob.startswith(_MAGIC):
            _fail()
        return validate_token(_crypt(blob[len(_MAGIC):], decrypt=True).decode("ascii"))
    except Exception:
        _fail()


def _checked_path(value) -> Path:
    if not isinstance(value, (str, Path)):
        _fail()
    path = Path(value)
    if not path.is_absolute() or str(path).startswith(("\\\\", "//")) or ".." in path.parts:
        _fail()
    for part in path.parts[1:]:
        if (not part or part.endswith((".", " ")) or
                any(ord(c) < 32 or c in '<>:"/\\|?*' for c in part) or
                re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part)):
            _fail()
    # This lexical check happens before inspecting the requested filesystem.
    project = _PROJECT_ROOT.absolute()
    if path == project or path.is_relative_to(project):
        _fail()
    return path


def _physical_external(parent: Path) -> None:
    # Also catch drive/8.3 aliases, which are not marked as reparse points.
    physical = parent.resolve(strict=True)
    project = _PROJECT_ROOT.resolve(strict=True)
    if physical == project or physical.is_relative_to(project):
        _fail()


class _FileInfo(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME),
                ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME),
                ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]


class _Files:
    def __init__(self):
        if os.name != "nt":
            _fail()
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "CreateFileW": ([wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "GetFileInformationByHandle": ([wintypes.HANDLE, ctypes.POINTER(_FileInfo)], wintypes.BOOL),
            "GetFileAttributesW": ([wintypes.LPCWSTR], wintypes.DWORD),
            "WriteFile": ([wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
            "ReadFile": ([wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p], wintypes.BOOL),
            "FlushFileBuffers": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (args, result) in signatures.items():
            method = getattr(self.api, name)
            method.argtypes, method.restype = args, result

    def open(self, path: Path, *, directory=False, create=False):
        access = 0x80 if directory else (0x40000000 if create else 0x80000000)
        # Directories: share reads only, preventing concurrent rename/reparse
        # mutation throughout the prompt and operation. Files: exclusive write.
        share = 1 if directory or not create else 0
        flags = 0x00200000 | (0x02000000 if directory else 0x80)
        handle = self.api.CreateFileW(str(path), access, share, None, 1 if create else 3, flags, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            _fail()
        try:
            info = _FileInfo()
            if not self.api.GetFileInformationByHandle(handle, ctypes.byref(info)):
                _fail()
            if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
                _fail()
            if not directory and info.links != 1:
                _fail()
            return handle, (info.size_high << 32) | info.size_low
        except BaseException:
            self.api.CloseHandle(handle)
            raise


@contextmanager
def _locked_path(value, *, creating):
    path = _checked_path(value)
    files = _Files()
    handles = []
    try:
        # Inspect and pin every component using OPEN_REPARSE_POINT, never follow
        # junctions or symlinks. Parent must exist; we create no directories.
        for parent in reversed(path.parents):
            handle, _ = files.open(parent, directory=True)
            handles.append(handle)
        _physical_external(path.parent)
        if creating:
            attributes = files.api.GetFileAttributesW(str(path))
            if attributes != 0xFFFFFFFF or ctypes.get_last_error() != 2:
                _fail()
        yield path, files
    finally:
        for handle in reversed(handles):
            files.api.CloseHandle(handle)


class _PreparedOutput:
    def __init__(self, path, files):
        self.path, self.files, self.used = path, files, False

    def store(self, token: str) -> None:
        if self.used:
            _fail()
        self.used = True
        blob = protect_token(token)
        handle, _ = self.files.open(self.path, create=True)
        try:
            buffer = ctypes.create_string_buffer(blob, len(blob))
            written = wintypes.DWORD()
            if (not self.files.api.WriteFile(handle, buffer, len(blob), ctypes.byref(written), None)
                    or written.value != len(blob)
                    or not self.files.api.FlushFileBuffers(handle)):
                _fail()
        finally:
            self.files.api.CloseHandle(handle)


@contextmanager
def prepare_token_file(path):
    """Validate and pin an external, nonexistent output before hidden prompting."""
    try:
        with _locked_path(path, creating=True) as (checked, files):
            yield _PreparedOutput(checked, files)
    except Exception:
        _fail()


def store_token_file(path, token: str) -> None:
    with prepare_token_file(path) as output:
        output.store(token)


def load_token(path) -> str:
    try:
        with _locked_path(path, creating=False) as (checked, files):
            handle, size = files.open(checked)
            try:
                if not len(_MAGIC) < size <= _MAX_BLOB:
                    _fail()
                buffer = ctypes.create_string_buffer(size)
                read = wintypes.DWORD()
                if not files.api.ReadFile(handle, buffer, size, ctypes.byref(read), None) or read.value != size:
                    _fail()
                return unprotect_token(buffer.raw)
            finally:
                files.api.CloseHandle(handle)
    except Exception:
        _fail()
