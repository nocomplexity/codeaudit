# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import lzma
import os
import tempfile


# sast_meta data
SAST_META = {
    "title": "Insecure LZMA Stream Open (lzma.open)",   
    "cwe_id": 22,               # Path Traversal (also consider CWE-409 for decompression bomb)
    "weakness": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "owasp": "A01:2021 - Broken Access Control",
    "severity": "Medium",
    "cvss": None,               # Not a CVE-specific rating here
    "impact": "Medium",
    "tags": ["file-handling", "lzma", "lzma-open", "stream", "path-traversal", "decompression-bomb"],
}


# ---------- Unsafe pattern (for audit demonstration only) ----------
def unsafe_read_xz(user_supplied_path: str) -> bytes:
    """VULNERABLE: trusts caller-supplied path directly."""
    with lzma.open(user_supplied_path, "rb") as f:
        return f.read()


# ---------- Safe patterns using lzma.open ----------
def safe_read_text(path: str, base_dir: str, max_bytes: int = 10 * 1024 * 1024) -> str:
    """
    Read a text file compressed as .xz via lzma.open in text mode,
    with a confined path and a decompressed-size cap.
    """
    resolved = os.path.realpath(path)
    if not resolved.startswith(os.path.realpath(base_dir) + os.sep):
        raise PermissionError(f"Path escapes base directory: {path}")

    chunks, total = [], 0
    # Text mode with encoding lets lzma.open act like the built-in open()
    with lzma.open(resolved, "rt", encoding="utf-8") as f:
        for line in f:
            total += len(line.encode("utf-8"))
            if total > max_bytes:
                raise ValueError("Decompressed size exceeds limit (possible bomb).")
            chunks.append(line)
    return "".join(chunks)


def safe_write_xz(path: str, data: str, preset: int = 6) -> None:
    """Write compressed text using lzma.open with a preset (0-9 | PRESET_EXTREME)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with lzma.open(path, "wt", encoding="utf-8", preset=preset) as f:
        f.write(data)


def safe_append_xz(path: str, more_text: str) -> None:
    """Append to an .xz text file (mode 'at' or 'ab')."""
    with lzma.open(path, "at", encoding="utf-8") as f:
        f.write(more_text)


def inspect_first_line(path: str) -> str:
    """Read only the first line — proves lzma.open streams lazily."""
    with lzma.open(path, "rt", encoding="utf-8") as f:
        return f.readline().rstrip("\n")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "data")
        os.makedirs(base, exist_ok=True)
        xz_path = os.path.join(base, "notes.txt.xz")

        # Write, append, read, inspect — all through lzma.open
        safe_write_xz(xz_path, "line one\nline two\n", preset=9)
        safe_append_xz(xz_path, "line three\n")
        print("First line:", inspect_first_line(xz_path))
        print("Full text:\n" + safe_read_text(xz_path, base))