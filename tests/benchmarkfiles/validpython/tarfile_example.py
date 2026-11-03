# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


import tarfile
import os

# SAST Metadata
SAST_META = {
    "title": "Path Traversal via Tarfile Extraction",
    "cwe_id": [22, 59],         # 22 path traversal, 59 link following (symlink/hardlink)
    "weakness": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "owasp": "A01:2021 - Broken Access Control",
    "severity": "High",
    "cvss": 8.1,                # AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N (typical for filter bypass)
    "impact": "High",
    "tags": ["tarfile", "path-traversal", "symlink", "hardlink", "archive-extraction",
             "zip-slip", "arbitrary-write", "python"],
}


def demo_extractall_unsafe(archive_path, extract_dir):
    """Sink: TarFile.extractall with default/unsafe filter (pre-3.14 or explicit None)."""
    print(f"[extractall] archive={archive_path!r} -> {extract_dir!r}")
    with tarfile.open(archive_path) as tar:
        # Vulnerable on Python ≤ 3.13 with default filter=None (no filtering)
        # and on 3.14+ if filter='fully_trusted' is used explicitly.
        # A malicious member name like '../../etc/cron.d/evil' writes outside extract_dir.
        tar.extractall(extract_dir)


def demo_extract_unsafe(archive_path, extract_dir):
    """Sink: TarFile.extract on a single member with unsafe filter."""
    print(f"[extract] archive={archive_path!r} -> {extract_dir!r}")
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            # Vulnerable: same path traversal risk, member-by-member.
            # extract() does not handle all extraction issues (per docs).
            tar.extract(member, extract_dir)


def demo_filter_bypass_gadget(archive_path, extract_dir):
    """Illustrates known filter bypass vectors (informational — do NOT treat filter as silver bullet)."""
    print(f"[filter-bypass] archive={archive_path!r} -> {extract_dir!r}")
    with tarfile.open(archive_path) as tar:
        # Even with filter='data', historical CVEs show bypasses:
        # CVE-2025-4517: arbitrary write with filter='data'
        # CVE-2025-4330: symlink target outside destination
        # CVE-2025-4138: arbitrary symlink creation
        # CVE-2026-7774: crafted symlink names bypass data_filter
        # CVE-2026-11940: hardlink referencing symlink bypasses filter
        try:
            tar.extractall(extract_dir, filter="data")
            print("  [note] filter='data' applied — but verify Python version is patched")
        except (tarfile.FilterError, tarfile.ExtractError) as e:
            print(f"  [blocked] filter rejected member: {e}")


def safe_extract_with_validation(archive_path, extract_dir):
    """Defense-in-depth: canonicalize and verify every member stays within extract_dir."""
    print(f"[safe] archive={archive_path!r} -> {extract_dir!r}")
    base = os.path.realpath(extract_dir)
    with tarfile.open(archive_path) as tar:
        for member in tar.getmembers():
            # Resolve the member's final path
            target = os.path.realpath(os.path.join(base, member.name))
            # Reject absolute paths and any escape via .. or symlink resolution
            if not target.startswith(base + os.sep) and target != base:
                print(f"  [REJECT] {member.name!r} resolves outside {base!r}")
                continue
            # Reject links whose targets contain parent-directory segments
            if member.issym() or member.islnk():
                if os.pardir in os.path.split(member.linkname):
                    print(f"  [REJECT] link {member.name!r} -> {member.linkname!r} contains '..'")
                    continue
            tar.extract(member, extract_dir, filter="data")


if __name__ == "__main__":
    print("[*] tarfile extraction sinks (intentionally vulnerable demo)\n")

    # Helper to craft a traversal archive for demonstration
    def craft_traversal_tar(path):
        import io
        with tarfile.open(path, "w") as tar:
            info = tarfile.TarInfo(name="../../pwned.txt")
            data = b"attacker controlled content"
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

    archive = "/tmp/demo_traversal.tar"
    craft_traversal_tar(archive)

    demo_extractall_unsafe(archive, "/tmp/extract_target")
    print()
    demo_extract_unsafe(archive, "/tmp/extract_target")
    print()
    demo_filter_bypass_gadget(archive, "/tmp/extract_target")
    print()
    safe_extract_with_validation(archive, "/tmp/extract_target")

    # Cleanup
    for p in (archive, "/tmp/pwned.txt"):
        try:
            os.remove(p)
        except FileNotFoundError:
            pass

    print("\n[*] Safe alternative: validate-then-extract (see safe_extract_with_validation)")