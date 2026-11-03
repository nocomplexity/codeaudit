# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import sys
import pickle
import io

# SAST Metadata
SAST_META = {
    "title": "Insecure Deserialization (pickle.loads / pickle.load / pickle.Unpickler)",
    "cwe_id": [502, 94, 915],   # 502 deserialization of untrusted data,
                                # 94 improper control of code generation (code injection),
                                # 915 improper modification of dynamically-determined object attributes
    "weakness": "Deserialization of Untrusted Data",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "severity": "High",
    "cvss": 9.8,
    "impact": "High",
    "tags": ["pickle", "deserialization", "rce", "code-execution",
             "untrusted-data", "python", "serialization"],
}


class Exploit:
    """A benign stand-in for a malicious pickle gadget.

    In a real attack, __reduce__ returns (callable, args) and pickle invokes
    that callable during unpickling — before any application logic runs.
    Here we just print; a real gadget would call os.system / subprocess.Popen.
    """
    def __reduce__(self):
        return (os.system, ("echo 'arbitrary code executed via pickle'",))


def demo_pickle_loads():
    """Sink 1: pickle.loads on an in-memory bytes blob."""
    payload = pickle.dumps(Exploit())
    print(f"[loads] payload size={len(payload)} bytes, source=bytes")
    # Vulnerable: untrusted bytes -> object graph -> arbitrary code
    result = pickle.loads(payload)
    print(f"[loads] returned: {result!r}")


def demo_pickle_load():
    """Sink 2: pickle.load on a file-like object."""
    payload = pickle.dumps(Exploit())
    buf = io.BytesIO(payload)  # stands in for an untrusted file
    print(f"[load]  source=file-like object (BytesIO)")
    # Vulnerable: path/stream supplied by caller, no trust check
    result = pickle.load(buf)
    print(f"[load]  returned: {result!r}")


def demo_pickle_unpickler():
    """Sink 3: pickle.Unpickler — same risk, just an explicit loader object."""
    payload = pickle.dumps(Exploit())
    buf = io.BytesIO(payload)
    print(f"[Unpickler] source=file-like object via explicit Unpickler")
    # Vulnerable: Unpickler is not a "safe" API — it is pickle's engine
    result = pickle.Unpickler(buf).load()
    print(f"[Unpickler] returned: {result!r}")


if __name__ == "__main__":
    print("[*] pickle deserialization sinks (intentionally vulnerable demo)")
    print("[*] Code execution fires DURING unpickling, before 'result' exists.\n")
    demo_pickle_loads()
    print()
    demo_pickle_load()
    print()
    demo_pickle_unpickler()

    print("\n[*] Safe alternative (for contrast): use JSON for untrusted data")
    import json
    safe = json.loads('{"user": "alice", "role": "viewer"}')
    print(f"    json.loads -> {safe}  (no code execution possible)")