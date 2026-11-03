# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import zipfile
import os

# SAST Metadata
SAST_META = {
    "title": "Path Traversal via Zipfile Extraction",
    "cwe_id": [22, 59],         # 22 path traversal, 59 link following (symlink)
    "weakness": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "owasp": "A01:2021 - Broken Access Control",
    "severity": "High",
    "cvss": 8.1,
    "impact": "High",
    "tags": ["zipfile", "path-traversal", "zip-slip", "arbitrary-write",
             "symlink", "archive-extraction", "python"],
}


def demo_extractall_unsafe(archive_path, extract_dir):
    """Sink: ZipFile.extractall with an untrusted archive (zip-slip)."""
    print(f"[extractall] archive={archive_path!r} -> {extract_dir!r}")
    with zipfile.ZipFile(archive_path) as zf:
        # Vulnerable: a member named '../../etc/cron.d/evil' writes outside
        # extract_dir. ZipFile.extractall does not sanitize member names.
        zf.extractall(extract_dir)


def demo_extract_unsafe(archive_path, extract_dir):
    """Sink: ZipFile.extract on a single member with an untrusted name."""
    print(f"[extract] archive={archive_path!r} -> {extract_dir!r}")
    with zipfile.ZipFile(archive_path) as zf:
        for name in zf.namelist():
            # Vulnerable: same traversal risk, member-by-member.
            zf.extract(name, extract_dir)


def safe_extract_with_validation(archive_path, extract_dir):
    """Defense-in-depth: canonicalize and verify every member stays within extract_dir."""
    print(f"[safe] archive={archive_path!r} -> {extract_dir!r}")
    base = os.path.realpath(extract_dir)
    with zipfile.ZipFile(archive_path) as zf:
        for name in zf.namelist():
            target = os.path.realpath(os.path.join(base, name))
            # Reject absolute paths and any escape via .. or symlink resolution
            if not target.startswith(base + os.sep) and target != base:
                print(f"  [REJECT] {name!r} resolves outside {base!r}")
                continue
            zf.extract(name, extract_dir)


if __name__ == "__main__":
    print("[*] zipfile extraction demo (intentionally vulnerable pattern)\n")

    # Craft a zip containing a traversal entry
    archive = "/tmp/demo_traversal.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../pwned.txt", b"attacker controlled content")
        zf.writestr("safe.txt", b"benign content")

    demo_extractall_unsafe(archive, "/tmp/extract_target")
    print()
    demo_extract_unsafe(archive, "/tmp/extract_target")
    print()
    safe_extract_with_validation(archive, "/tmp/extract_target")

    # Cleanup
    for p in (archive, "/tmp/pwned.txt"):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass

    print("\n[*] Safe alternative: validate-then-extract (see safe_extract_with_validation)")