# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import sys
import shutil
import tempfile


# sast_meta data
SAST_META = {
    "title": "Dangerous OS Command and Exec Family Usage",    
    "cwe_id": [78,367,88],                          
    "weakness": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "owasp": "A03:2021 - Injection",
    "severity": "High",
    "cvss": None,
    "impact": "High",
    "tags": ["os", "command-injection", "shell", "exec", "toctou", "os-system", "os-popen"],
}


def demo_os_access() -> None:
    """os.access: check readability/writability. NOT a security boundary."""
    target = "/etc/hostname" if os.path.exists("/etc/hostname") else __file__
    print(f"[os.access] can read {target}? -> {os.access(target, os.R_OK)}")
    print(f"[os.access] can exec {target}? -> {os.access(target, os.X_OK)}")


def demo_os_system() -> None:
    """os.system: runs a command through the shell. Injection risk if args are dynamic."""
    rc = os.system("echo '[os.system] hello from a shell'")
    print(f"[os.system] exit status = {rc}")


def demo_os_popen() -> None:
    """os.popen: opens a pipe to/from a shell command."""
    with os.popen("echo '[os.popen] captured output'") as pipe:
        out = pipe.read().strip()
    print(f"[os.popen] -> {out}")


def demo_exec_family() -> None:
    """
    Demonstrate the exec* family. Exec REPLACES the current process, so each
    variant is shown by forking first and letting the child exec.
    In real code, prefer subprocess.
    """
    # Pick a portable command: the Python interpreter itself.
    py = sys.executable or "python3"
    env_clean = {"PATH": os.environ.get("PATH", "")}
    env_full = os.environ.copy()

    # os.execl(path, arg0, arg1, ...)
    pid = os.fork()
    if pid == 0:
        os.execl(py, py, "-c", "import sys; print('[os.execl] ok'); sys.exit(0)")
        os._exit(127)
    os.waitpid(pid, 0)

    # os.execle(path, arg0, arg1, ..., env)
    pid = os.fork()
    if pid == 0:
        os.execle(py, py, "-c", "import sys; print('[os.execle] ok'); sys.exit(0)", env_clean)
        os._exit(127)
    os.waitpid(pid, 0)

    # os.execlp(file, arg0, arg1, ...)  — searches PATH
    pid = os.fork()
    if pid == 0:
        os.execlp("echo", "echo", "[os.execlp] ok")
        os._exit(127)
    os.waitpid(pid, 0)

    # os.execlpe(file, arg0, arg1, ..., env) — PATH search + env
    pid = os.fork()
    if pid == 0:
        os.execlpe("echo", "echo", "[os.execlpe] ok", env_clean)
        os._exit(127)
    os.waitpid(pid, 0)

    # os.execv(path, args_list)
    pid = os.fork()
    if pid == 0:
        os.execv(py, [py, "-c", "import sys; print('[os.execv] ok'); sys.exit(0)"])
        os._exit(127)
    os.waitpid(pid, 0)

    # os.execve(path, args_list, env)
    pid = os.fork()
    if pid == 0:
        os.execve(py, [py, "-c", "import sys; print('[os.execve] ok'); sys.exit(0)"], env_full)
        os._exit(127)
    os.waitpid(pid, 0)

    # os.execvp(file, args_list) — PATH search
    pid = os.fork()
    if pid == 0:
        os.execvp("echo", ["echo", "[os.execvp] ok"])
        os._exit(127)
    os.waitpid(pid, 0)

    # os.execvpe(file, args_list, env) — PATH search + env
    pid = os.fork()
    if pid == 0:
        os.execvpe("echo", ["echo", "[os.execvpe] ok"], env_clean)
        os._exit(127)
    os.waitpid(pid, 0)


if __name__ == "__main__":
    demo_os_access()
    demo_os_system()
    demo_os_popen()
    if hasattr(os, "fork"):
        demo_exec_family()
    else:
        print("[exec family] skipped: os.fork not available on this platform")