# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


import lzma
import os
import tempfile

# sast_meta data
SAST_META = {
    "title": "Insecure LZMA Archive Handling",   
    "cwe_id": 22,         # Path Traversal (also consider CWE-409 for decompression bomb)
    "weakness": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "owasp": "A01:2021 - Broken Access Control",
    "severity": "Medium",
    "cvss": None,               # Not a CVE-specific rating here
    "impact": "Medium",
    "tags": ["file-handling", "lzma", "archive", "path-traversal", "decompression-bomb"],
}


def compress_file(source_path: str, archive_path: str) -> None:
    """Compress a file into an .xz archive using lzma.LZMAFile."""
    with open(source_path, "rb") as src, lzma.LZMAFile(archive_path, "wb") as dst:
        while chunk := src.read(64 * 1024):
            dst.write(chunk)


def decompress_file(archive_path: str, dest_path: str) -> None:
    """Safely decompress an .xz archive with size limits."""
    MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB safety limit
    written = 0

    with lzma.LZMAFile(archive_path, "rb") as src, open(dest_path, "wb") as dst:
        while chunk := src.read(64 * 1024):
            written += len(chunk)
            if written > MAX_UNCOMPRESSED_BYTES:
                raise ValueError("Decompression limit exceeded (possible bomb).")
            dst.write(chunk)


def stream_inspect(archive_path: str) -> None:
    """Read an LZMA stream incrementally without materializing it."""
    with lzma.LZMAFile(archive_path, "rb") as f:
        header = f.read(16)
        print(f"First 16 bytes: {header!r}")
        # seek/read behave like a regular binary file object
        f.seek(0)
        print(f"Total decompressed size (bytes): {len(f.read())}")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        src_file = os.path.join(tmp, "sample.txt")
        archive = os.path.join(tmp, "sample.txt.xz")
        out_file = os.path.join(tmp, "sample.out.txt")

        with open(src_file, "w", encoding="utf-8") as f:
            f.write("Hello from lzma.LZMAFile!\n" * 100)

        compress_file(src_file, archive)
        print(f"Archive size: {os.path.getsize(archive)} bytes")

        stream_inspect(archive)
        decompress_file(archive, out_file)

        with open(out_file, "r", encoding="utf-8") as f:
            print("Round-trip OK:", f.read(40).strip())