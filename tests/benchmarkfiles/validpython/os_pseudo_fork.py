# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 
import os
import sys
import select

# SAST Metadata
SAST_META = {
    "title": "Insecure Pseudo-Terminal Forking (os.forkpty) - Terminal Escape and FD Leak",
    "cwe_id": [362, 829, 78],   # 362 race condition, 829 include functionality from untrusted control sphere (pty escape),
                                # 78 OS command injection (via forked shell in pty)
    "weakness": "Concurrent Execution using Shared Resource with Improper Synchronization",
    "owasp": "A04:2021 - Insecure Design",
    "severity": "Low",
    "cvss": None,
    "impact": "Low",
    "tags": ["os", "forkpty", "pty", "pseudo-terminal", "process-management",
             "race-condition", "fd-leak", "terminal-escape"],
}


def demonstrate_forkpty():
    """
    Demonstrates os.forkpty() usage.

    os.forkpty() forks a child process AND creates a new pseudo-terminal,
    making the child the session leader with the pty as its controlling terminal.
    Returns (pid, fd) where pid=0 in child and fd is the pty master fd.

    NOTE: Unix-only.
    """
    print(f"[Parent] PID={os.getpid()} starting forkpty demo")

    try:
        pid, master_fd = os.forkpty()
    except OSError as e:
        print(f"[Parent] forkpty failed: {e}")
        sys.exit(1)

    if pid == 0:
        # ---- Child: stdin/stdout/stderr are already the pty slave ----
        print("[Child] running inside pseudo-terminal")
        sys.stdout.flush()
        # Simulate a child program that reads from its terminal
        data = sys.stdin.readline()
        print(f"[Child] received: {data.strip()}")
        os._exit(0)
    else:
        # ---- Parent: talk to child through the pty master fd ----
        print(f"[Parent] child PID={pid}, pty master fd={master_fd}")

        # Write a line to the child's terminal
        os.write(master_fd, b"hello-from-parent\n")

        # Read the child's response from the pty
        output = b""
        while True:
            try:
                chunk = os.read(master_fd, 1024)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            # In a real app you'd use select() with a timeout here
            if b"received:" in output:
                break

        print(f"[Parent] pty output: {output.decode(errors='replace').strip()}")

        # Reap the child to avoid a zombie
        _, status = os.waitpid(pid, 0)
        print(f"[Parent] child exited with status {status}")
        os.close(master_fd)


if __name__ == "__main__":
    if not hasattr(os, "forkpty"):
        print("os.forkpty is not available on this platform (Windows).")
        sys.exit(0)
    demonstrate_forkpty()