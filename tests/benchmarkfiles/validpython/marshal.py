# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import marshal
import os
import tempfile
import types


# sast_meta data
SAST_META = {
    "title": "Deserialization of Untrusted Data via marshal",   
    "cwe_id": 502,              # Deserialization of Untrusted Data                                
    "weakness": "Deserialization of Untrusted Data",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "severity": "High",
    "cvss": None,
    "impact": "High",
    "tags": ["marshal", "deserialization", "code-execution", "pyc", "unsafe-serialization"],
}


# ---------- Legitimate use: marshal round-trip of trusted objects ----------
def roundtrip_trusted_example() -> None:
    """
    Safe round-trip: we produce the bytes ourselves and consume them
    in the same process. marshal is used here as a fast, compact
    serializer for a handful of primitives and code objects.
    """
    payload = {
        "version": 1,
        "name": "demo",
        "values": [1, 2, 3, 4],
        "nested": {"ok": True, "score": 0.95},
    }

    blob = marshal.dumps(payload)                       # -> bytes
    loaded = marshal.loads(blob)                        # -> object
    assert loaded == payload
    print("Round-trip OK:", loaded["name"], loaded["values"])


# ---------- Legitimate use: reading a .pyc file you produced yourself ----------
def load_trusted_pyc(path: str, trusted_dir: str) -> types.CodeType:
    """
    Load a compiled code object from a .pyc file that lives under a
    directory we control. marshal.load reads a code object from the
    file's byte stream — this is exactly how CPython loads .pyc files.
    """
    resolved = os.path.realpath(path)
    if not resolved.startswith(os.path.realpath(trusted_dir) + os.sep):
        raise PermissionError(f"Pyc path escapes trusted directory: {path}")

    with open(resolved, "rb") as f:
        # First 16 bytes are the .pyc header (magic + flags + mtime/size),
        # depending on Python version; the code object follows.
        header = f.read(16)
        code = marshal.load(f)                          # trusted file
        print(f"Loaded code object '{code.co_name}' from {header.hex()[:8]}... header")
        return code


# ---------- UNSAFE patterns (shown for audit demonstration only) ----------
def unsafe_loads_from_network(data: bytes):
    """VULNERABLE: deserializes attacker-controlled bytes."""
    return marshal.loads(data)


def unsafe_load_from_world_writable(path: str):
    """VULNERABLE: opens a path an attacker may be able to write."""
    with open(path, "rb") as f:
        return marshal.load(f)

