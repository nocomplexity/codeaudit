# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import tempfile


# sast_meta data
SAST_META = {
    "title": "Unsafe Raw File Descriptor I/O (os.read / os.write / os.writev)",   
    "cwe_id": [22, 20, 400],    # 22 path traversal, 20 improper input validation,
                                # 400 uncontrolled resource consumption (fd leaks)
    "weakness": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "owasp": "A01:2021 - Broken Access Control",
    "severity": "Medium",
    "cvss": None,
    "impact": "Medium",
    "tags": ["os", "file-io", "file-descriptor", "os-read", "os-write", "os-writev", "path-traversal"],
}


# ---------- os.write ----------
def write_with_os_write(fd: int, data: bytes) -> int:
    """
    os.write writes to a file descriptor and may write FEWER bytes than
    requested. Loop until the whole buffer is written.
    """
    total = 0
    while total < len(data):
        written = os.write(fd, data[total:])
        if written == 0:
            raise OSError("os.write returned 0 — device or pipe closed")
        total += written
    return total


# ---------- os.writev ----------
def write_with_os_writev(fd: int, chunks: list[bytes]) -> int:
    """
    os.writev scatters a LIST of buffers to a file descriptor in one syscall
    (scatter/gather I/O). It also may write fewer bytes than sum(len(c)),
    so the caller must handle partial writes. The return value counts bytes,
    not buffer elements.
    """
    total = 0
    pending = list(chunks)
    while pending:
        written = os.writev(fd, pending)
        if written == 0:
            raise OSError("os.writev returned 0 — device or pipe closed")
        total += written
        # Drop fully written buffers; split a partially written one.
        while pending and written >= len(pending[0]):
            written -= len(pending[0])
            pending.pop(0)
        if pending and written:
            pending[0] = pending[0][written:]
    return total


# ---------- os.read ----------
def read_with_os_read(fd: int, max_bytes: int = 64 * 1024) -> bytes:
    """
    os.read returns AT MOST max_bytes; short reads are normal.
    Loop until EOF (empty bytes) or the cap is reached.
    """
    parts = []
    remaining = max_bytes
    while remaining > 0:
        chunk = os.read(fd, min(remaining, 64 * 1024))
        if not chunk:              # EOF
            break
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


# ---------- Safe path confinement helper ----------
def safe_open_for_io(path: str, base_dir: str, flags: int) -> int:
    """
    Open a path for raw fd I/O AFTER confining it to base_dir.
    Never hand a user-supplied path straight to os.open.
    """
    resolved = os.path.realpath(path)
    if not resolved.startswith(os.path.realpath(base_dir) + os.sep):
        raise PermissionError(f"Path escapes base directory: {path}")
    return os.open(resolved, flags, 0o600)


# ---------- Unsafe pattern, shown for audit demonstration only ----------
def unsafe_open_user_path(user_path: str) -> int:
    """VULNERABLE: user-controlled path straight into os.open."""
    return os.open(user_path, os.O_RDWR | os.O_CREAT)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "fd_demo.bin")

        # writev: scatter several buffers into one file
        fd = safe_open_for_io(target, tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        try:
            n = write_with_os_writev(fd, [b"alpha|", b"beta|", b"gamma\n"])
            print(f"[os.writev] wrote {n} bytes")
        finally:
            os.close(fd)

        # write: append a line through a raw fd
        fd = safe_open_for_io(target, tmp, os.O_WRONLY | os.O_APPEND)
        try:
            n = write_with_os_write(fd, b"delta\n")
            print(f"[os.write]  wrote {n} bytes")
        finally:
            os.close(fd)

        # read: pull it all back through os.read
        fd = safe_open_for_io(target, tmp, os.O_RDONLY)
        try:
            data = read_with_os_read(fd)
            print(f"[os.read]   read {len(data)} bytes: {data!r}")
        finally:
            os.close(fd)