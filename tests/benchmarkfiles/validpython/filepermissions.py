# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import stat
import tempfile


# sast_meta data
SAST_META = {
    "title": "Insecure File Permission Change (os.chmod)",   
    "cwe_id": [732, 22, 59],    # 732 incorrect permission assignment, 22 path traversal,
                                # 59 link following (symlink race)
    "weakness": "Incorrect Permission Assignment for Critical Resource",
    "owasp": "A01:2021 - Broken Access Control",
    "severity": "High",
    "cvss": None,
    "impact": "High",
    "tags": ["os", "file-permissions", "chmod", "access-control", "path-traversal", "symlink"],
}


# ---------- Safe pattern: chmod to a minimal, fixed mode ----------
def secure_file(path: str, base_dir: str, mode: int = 0o600) -> None:
    """
    Confine the path to base_dir, refuse to follow symlinks, then apply a
    minimal mode (default 0o600 = owner read/write only).
    """
    resolved = os.path.realpath(path)
    if not resolved.startswith(os.path.realpath(base_dir) + os.sep):
        raise PermissionError(f"Path escapes base directory: {path}")
    if os.path.islink(path):
        raise PermissionError(f"Refusing to chmod a symlink: {path}")

    os.chmod(resolved, mode)
    actual = stat.S_IMODE(os.stat(resolved).st_mode)
    print(f"[os.chmod] {resolved} -> {oct(actual)}")


# ---------- Safe pattern: drop group/other write bits from an existing file ----------
def remove_world_write(path: str) -> None:
    """Clear group and other write bits while preserving the rest."""
    current = stat.S_IMODE(os.stat(path).st_mode)
    hardened = current & ~(stat.S_IWGRP | stat.S_IWOTH)
    os.chmod(path, hardened)
    print(f"[os.chmod] {path}: {oct(current)} -> {oct(hardened)}")


# ---------- Safe pattern: lock down a directory ----------
def secure_dir(path: str) -> None:
    """0o700 = owner rwx only, group/other get nothing."""
    os.chmod(path, 0o700)
    print(f"[os.chmod] dir {path} -> {oct(stat.S_IMODE(os.stat(path).st_mode))}")


# ---------- Symbolic-style via stat constants ----------
def make_owner_readonly(path: str) -> None:
    """Express permissions with stat.* constants instead of raw octal."""
    mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH   # 0o444
    os.chmod(path, mode)
    print(f"[os.chmod] {path} -> {oct(stat.S_IMODE(os.stat(path).st_mode))}")


# ---------- UNSAFE patterns, shown for audit demonstration only ----------
def unsafe_world_writable(path: str) -> None:
    """VULNERABLE: any user on the host can read and modify the file."""
    os.chmod(path, 0o777)


def unsafe_user_path_mode(user_path: str, user_mode: int) -> None:
    """VULNERABLE: trusts both path and mode from the caller."""
    os.chmod(user_path, user_mode)


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        secret = os.path.join(tmp, "secret.txt")
        with open(secret, "w", encoding="utf-8") as f:
            f.write("sensitive\n")

        secure_file(secret, tmp)                    # -> 0o600
        os.chmod(secret, 0o666)
        remove_world_write(secret)                  # -> 0o644
        make_owner_readonly(secret)                 # -> 0o444

        private_dir = os.path.join(tmp, "private")
        os.makedirs(private_dir)
        secure_dir(private_dir)                     # -> 0o700