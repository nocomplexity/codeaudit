# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import tempfile

# SAST Metadata
SAST_META = {
    "title": "Insecure Temporary File Creation via tempfile.mktemp (TOCTOU Race Condition)",
    "cwe_id": [377, 367],       # 377 insecure temporary file, 367 time-of-check time-of-use (TOCTOU) race condition
    "weakness": "Insecure Temporary File",
    "owasp": "A01:2021 - Broken Access Control",
    "severity": "Low",
    "cvss": 7.0,                # AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N (typical local race)
    "impact": "High",
    "tags": ["tempfile", "mktemp", "race-condition", "toctou", "symlink-attack",
             "insecure-temp-file", "python"],
}


def demo_mktemp_race():
    """Sink: tempfile.mktemp returns a name, but does NOT create the file."""
    print("[mktemp] generating a temporary filename (insecure)")

    # Vulnerable: mktemp returns a path that does not exist yet.
    # Between this call and the open() below, another process can:
    #   - create a symlink at that path pointing to /etc/passwd
    #   - create a file with attacker-controlled content
    tmp_path = tempfile.mktemp(suffix=".log", prefix="app_")
    print(f"  mktemp returned: {tmp_path!r} (file does not exist yet)")

    # TOCTOU window: attacker can act here
    try:
        with open(tmp_path, "w") as f:
            f.write("sensitive application data\n")
        print(f"  wrote to {tmp_path!r} — but we do not control what it is")
    except OSError as e:
        print(f"  open failed: {e}")


def demo_mktemp_symlink_attack():
    """Demonstrates the symlink attack vector (conceptual — not executed)."""
    print("[mktemp symlink vector] (conceptual)")
    print("  1. App calls tempfile.mktemp() -> returns '/tmp/app_abc123.log'")
    print("  2. Attacker creates symlink: /tmp/app_abc123.log -> /etc/cron.d/evil")
    print("  3. App calls open(tmp_path, 'w') -> follows symlink, writes to /etc/cron.d/evil")
    print("  4. If app runs with privilege, attacker achieves arbitrary write")
    # The root cause: mktemp only generates a NAME, it does not atomically CREATE the file.


def safe_alternative_mkstemp():
    """Safe: tempfile.mkstemp atomically creates the file and returns (fd, path)."""
    print("[mkstemp] safe alternative — atomic create + open")
    fd, path = tempfile.mkstemp(suffix=".log", prefix="app_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("sensitive application data\n")
        print(f"  safely wrote to {path!r} (fd={fd} was opened atomically)")
    finally:
        os.unlink(path)   # cleanup


def safe_alternative_named_temporary_file():
    """Safe: NamedTemporaryFile manages creation and cleanup."""
    print("[NamedTemporaryFile] safe alternative — context-managed")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                     prefix="app_", delete=True) as f:
        f.write("sensitive application data\n")
        f.flush()
        print(f"  safely wrote to {f.name!r} (auto-deleted on close)")


if __name__ == "__main__":
    print("[*] tempfile.mktemp demo (intentionally vulnerable pattern)\n")
    demo_mktemp_race()
    print()
    demo_mktemp_symlink_attack()
    print()
    safe_alternative_mkstemp()
    print()
    safe_alternative_named_temporary_file()

    print("\n[*] Key takeaway: mktemp() returns a name, not a file.")
    print("    Always use mkstemp() / mkdtemp() / NamedTemporaryFile for atomic safety.")