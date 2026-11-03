# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import sys

# SAST Metadata
SAST_META = {
    "title": "Insecure Process Forking (os.fork) - Uncontrolled Child Process Execution",
    "cwe_id": [362, 364, 78],   # 362 race condition, 364 signal handler, 
                                # 78 OS command injection (via forked shell)
    "weakness": "Concurrent Execution using Shared Resource with Improper Synchronization",
    "owasp": "A04:2021 - Insecure Design",
    "severity": "Low",
    "cvss": None,
    "impact": "Low",
    "tags": ["os", "fork", "process-management", "race-condition", 
             "privilege", "resource-leak", "concurrency"],
}


def demonstrate_fork():
    """
    Demonstrates os.fork() usage.
    
    NOTE: os.fork() is only available on Unix-like systems (not Windows).
    """
    print(f"[Parent] PID={os.getpid()} starting fork demo")

    try:
        pid = os.fork()
    except OSError as e:
        print(f"[Parent] Fork failed: {e}")
        sys.exit(1)

    if pid == 0:
        # Child process branch
        print(f"[Child]  PID={os.getpid()}  Parent PID={os.getppid()}  "
              f"fork() returned {pid}")
        # Child does its own work
        try:
            # Simulated child work
            print("[Child]  performing child-only task...")
        finally:
            os._exit(0)   # _exit avoids running parent's atexit handlers / flushing twice
    else:
        # Parent process branch
        print(f"[Parent] PID={os.getpid()}  fork() returned child PID={pid}")
        # Parent should reap the child to avoid zombies
        try:
            _, status = os.waitpid(pid, 0)
            print(f"[Parent] Child {pid} exited with status {status}")
        except ChildProcessError:
            print(f"[Parent] Child {pid} already reaped")


if __name__ == "__main__":
    if not hasattr(os, "fork"):
        print("os.fork is not available on this platform (Windows).")
        sys.exit(0)
    demonstrate_fork()