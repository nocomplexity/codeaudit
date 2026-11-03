# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import subprocess
import shlex

# SAST Metadata
SAST_META = {
    "title": "OS Command Injection via subprocess Module (run/Popen/call/check_call/check_output/getoutput/getstatusoutput)",
    "cwe_id": [78, 77, 88],     # 78 OS command injection, 77 command injection,
                                # 88 argument injection (leading-dash argument confusion)
    "weakness": "Improper Neutralization of Special Elements used in an OS Command",
    "owasp": "A03:2021 - Injection",
    "severity": "High",
    "cvss": 9.8,
    "impact": "High",
    "tags": ["subprocess", "command-injection", "shell-true", "argument-injection",
             "rce", "python", "os-command"],
}


def demo_run(user_input):
    """Sink: subprocess.run with shell=True and concatenated input."""
    print(f"[run] input={user_input!r}")
    # Vulnerable: shell interprets metacharacters (; | && $())
    subprocess.run(f"echo {user_input}", shell=True)


def demo_popen(user_input):
    """Sink: subprocess.Popen with shell=True."""
    print(f"[Popen] input={user_input!r}")
    proc = subprocess.Popen(f"echo {user_input}", shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, _ = proc.communicate()
    print(f"[Popen] output={out.decode().strip()!r}")


def demo_call(user_input):
    """Sink: subprocess.call with shell=True."""
    print(f"[call] input={user_input!r}")
    subprocess.call(f"echo {user_input}", shell=True)


def demo_check_call(user_input):
    """Sink: subprocess.check_call with shell=True."""
    print(f"[check_call] input={user_input!r}")
    try:
        subprocess.check_call(f"echo {user_input}", shell=True)
    except subprocess.CalledProcessError as e:
        print(f"[check_call] non-zero exit: {e.returncode}")


def demo_check_output(user_input):
    """Sink: subprocess.check_output with shell=True."""
    print(f"[check_output] input={user_input!r}")
    try:
        out = subprocess.check_output(f"echo {user_input}", shell=True)
        print(f"[check_output] output={out.decode().strip()!r}")
    except subprocess.CalledProcessError as e:
        print(f"[check_output] failed: {e.returncode}")


def demo_getoutput(user_input):
    """Sink: subprocess.getoutput — implicitly uses shell=True."""
    print(f"[getoutput] input={user_input!r}")
    # getoutput always invokes /bin/sh -c on POSIX
    out = subprocess.getoutput(f"echo {user_input}")
    print(f"[getoutput] output={out.strip()!r}")


def demo_getstatusoutput(user_input):
    """Sink: subprocess.getstatusoutput — implicitly uses shell=True."""
    print(f"[getstatusoutput] input={user_input!r}")
    status, out = subprocess.getstatusoutput(f"echo {user_input}")
    print(f"[getstatusoutput] status={status} output={out.strip()!r}")


if __name__ == "__main__":
    print("[*] subprocess command-injection sinks (intentionally vulnerable demo)\n")

    # Simulated attacker payload — semicolon breaks out of echo, id runs
    payload = "hello; id"

    demo_run(payload)
    print()
    demo_popen(payload)
    print()
    demo_call(payload)
    print()
    demo_check_call(payload)
    print()
    demo_check_output(payload)
    print()
    demo_getoutput(payload)
    print()
    demo_getstatusoutput(payload)

    print("\n[*] Safe alternatives (for contrast):")
    safe_input = "hello; id"   # same payload

    # 1) Argument list, shell=False — semicolon is a literal argument
    subprocess.run(["echo", safe_input], shell=False)
    print("    run(list, shell=False) — payload treated as literal data")

    # 2) shlex.split for pre-built command strings
    subprocess.run(shlex.split("echo hello"), shell=False)
    print("    shlex.split + list — no shell interpretation")

    # 3) shlex.quote when a string command is unavoidable
    subprocess.run(f"echo {shlex.quote(safe_input)}", shell=True)
    print("    shlex.quote — metacharacters escaped for the shell")