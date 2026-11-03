# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

from compression import zstd

# SAST Metadata
SAST_META = {
    "title": "Insecure Zstandard Decompression",
    "cwe_id": [400, 409],       # 400 uncontrolled resource consumption (decompression bomb),
                                # 409 improper handling of unverified compressed data
    "weakness": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
    "owasp": "A04:2021 - Insecure Design",
    "severity": "Medium",
    "cvss": 7.5,                # AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (DoS)
    "impact": "Medium",
    "tags": ["zstd", "compression", "decompression-bomb", "memory-exhaustion",
             "denial-of-service", "untrusted-input", "python"],
}


def demo_decompress_unsafe(compressed_data):
    """Sink: zstd.decompress on untrusted input (one-shot, unbounded)."""
    print(f"[decompress] input size={len(compressed_data)} bytes")
    # Vulnerable: a small crafted .zst payload can expand to gigabytes,
    # exhausting memory before the function returns.
    result = zstd.decompress(compressed_data)
    print(f"[decompress] output size={len(result)} bytes")


def demo_open_unsafe(archive_path):
    """Sink: zstd.open reading from an untrusted file."""
    print(f"[open] path={archive_path!r}")
    with zstd.open(archive_path) as f:
        # Vulnerable: read() pulls the entire decompressed stream into memory.
        # A decompression bomb causes OOM during the read.
        content = f.read()
    print(f"[open] read {len(content)} bytes")


if __name__ == "__main__":
    print("[*] zstd decompression demo (intentionally vulnerable pattern)\n")

    # Craft a highly compressible payload (a "bomb" in miniature)
    bomb_data = b"\x00" * (50 * 1024 * 1024)  # 50 MB of zeros
    compressed = zstd.compress(bomb_data)
    print(f"[demo] crafted {len(compressed)}-byte payload -> "
          f"{len(bomb_data)}-byte expansion\n")

    demo_decompress_unsafe(compressed)
    print()

    # Write a .zst file for the open() demo
    with open("/tmp/demo.zst", "wb") as f:
        f.write(compressed)
    demo_open_unsafe("/tmp/demo.zst")

    print("\n[*] Safe alternative: use ZstdDecompressor with max_length")
    # Streaming decompression with an explicit output bound
    dec = zstd.ZstdDecompressor()
    out = dec.decompress(compressed, max_length=1024 * 1024)  # cap at 1 MiB
    print(f"    ZstdDecompressor.decompress(max_length=1MiB) -> {len(out)} bytes returned")
    print("    (remaining output is buffered; caller decides whether to continue)")