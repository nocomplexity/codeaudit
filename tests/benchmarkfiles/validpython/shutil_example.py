# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import sys
import shutil
import tempfile

# SAST Metadata
SAST_META = {
    "title": "Insecure File Operations via shutil (Path Traversal, Symlink, and Permission Risks)",
    "cwe_id": [22, 59, 732],    # 22 path traversal, 59 link following (symlink),
                                # 732 incorrect permission assignment (setuid/setgid preservation)
    "weakness": "Improper Limitation of a Pathname to a Restricted Directory",
    "owasp": "A01:2021 - Broken Access Control",
    "severity": "Medium",
    "cvss": None,
    "impact": "Medium",
    "tags": ["shutil", "path-traversal", "symlink", "zip-slip", "file-permissions",
             "setuid", "copytree", "unpack-archive", "rmtree"],
}


def demo_copytree(user_supplied_name):
    """Sink: shutil.copytree with attacker-influenced destination."""
    src = "/tmp/safe_source"
    # Vulnerable: user_supplied_name can contain "../" to escape the base
    dst = os.path.join("/tmp/uploads", user_supplied_name)
    print(f"[copytree] dst={dst!r}")
    # If user_supplied_name = "../../etc/cron.d", writes outside intended root
    shutil.copytree(src, dst)  # uncomment to demo escape


def demo_copy_copy2(user_supplied_path):
    """Sink: shutil.copy / copy2 with untrusted path."""
    src = "/tmp/safe_source/file.txt"
    print(f"[copy2] src={src!r} dst={user_supplied_path!r}")
    # Path traversal: user_supplied_path = "/etc/shadow" -> overwrites
    # Symlink risk: if dst is a symlink, copy follows it by default
    shutil.copy2(src, user_supplied_path)


def demo_unpack_archive(user_supplied_archive):
    """Sink: shutil.unpack_archive with untrusted archive and destination."""
    extract_dir = "/tmp/extracted"
    print(f"[unpack_archive] archive={user_supplied_archive!r} -> {extract_dir!r}")
    # Zip-slip risk: archive entries with ../ escape extract_dir
    # CVE-2026-12345-adjacent: Windows drive-letter paths bypass checks
    shutil.unpack_archive(user_supplied_archive, extract_dir)


def demo_chown(user_supplied_path):
    """Sink: shutil.chown with untrusted path (Unix-only)."""
    print(f"[chown] path={user_supplied_path!r} user='nobody'")
    # Path traversal: attacker targets arbitrary file ownership change
    # Requires sufficient privileges to actually chown
    shutil.chown(user_supplied_path, user="nobody")


def demo_rmtree(user_supplied_path):
    """Sink: shutil.rmtree with untrusted path."""
    print(f"[rmtree] path={user_supplied_path!r}")
    # Path traversal: user_supplied_path = "/" or "/home" -> destructive
    # Symlink race on platforms without rmtree.avoids_symlink_attacks
    shutil.rmtree(user_supplied_path)


if __name__ == "__main__":
    print("[*] shutil sinks (intentionally vulnerable demo)\n")

    # Simulated attacker inputs
    demo_copytree("../escaped-target")
    print()
    demo_copy_copy2("/etc/passwd")
    print()
    demo_unpack_archive("/tmp/upload.zip")
    print()
    demo_chown("../../etc/shadow")
    print()
    demo_rmtree("../../important-data")

    print("\n[*] Safe pattern (for contrast): canonicalize-then-verify-prefix")
    base = "/tmp/uploads"
    user_input = "../escaped"
    resolved = os.path.realpath(os.path.join(base, user_input))
    if not resolved.startswith(os.path.realpath(base) + os.sep):
        print(f"    Blocked traversal: {resolved!r} not under {base!r}")
    else:
        print(f"    Allowed: {resolved!r}")