# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import sys

# SAST Metadata
SAST_META = {
    "title": "Python Tracing/Profiling Hooks",
    "cwe_id": [94, 829, 400],   # 94 code injection, 829 include functionality from untrusted control sphere,
                                # 400 uncontrolled resource consumption (DoS via tracing overhead)
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "severity": "Medium",
    "cvss": None,
    "impact": "Medium",
    "tags": ["sys", "settrace", "setprofile", "call_tracing", "introspection",
             "code-injection", "information-disclosure", "backdoor", "sandbox-escape"],
}


def demo_settrace():
    """Sink: sys.settrace — line-level execution monitoring and modification."""
    print("[settrace] installing trace hook")

    def trace_calls(frame, event, arg):
        if event == "call":
            print(f"  -> entering {frame.f_code.co_name}")
        return trace_calls   # enables line-level events within the frame

    # Vulnerable: a malicious trace function can read f_locals, modify execution,
    # or silently log credentials/keys. Installed early, it persists undetected.
    sys.settrace(trace_calls)

    def sensitive_function(password):
        # The trace hook can read frame.f_locals["password"] here
        return len(password)

    sensitive_function("s3cr3t-api-key")
    sys.settrace(None)   # always disable after use


def demo_setprofile():
    """Sink: sys.setprofile — function-level call/return/exception monitoring."""
    print("[setprofile] installing profile hook")

    def profile_calls(frame, event, arg):
        if event == "call":
            print(f"  -> call: {frame.f_code.co_name}")

    # Vulnerable: same data-access risk as settrace (frame.f_locals/f_globals),
    # plus visibility into C-level calls. Can be used for stealthy surveillance.
    sys.setprofile(profile_calls)

    def another_sensitive(api_key):
        return api_key

    another_sensitive("sk-live-abc123")
    sys.setprofile(None)


def demo_call_tracing():
    """Sink: sys.call_tracing — calls a function WITH tracing re-enabled."""
    print("[call_tracing] tracing a specific call")

    def trace_calls(frame, event, arg):
        if event == "call":
            print(f"  -> traced: {frame.f_code.co_name}")
        return None

    sys.settrace(trace_calls)

    def target(x):
        return x * 2

    # Vulnerable: call_tracing deliberately bypasses the normal tracing suspension
    # inside trace functions, enabling recursive tracing — useful for debuggers,
    # but also for attackers who want to monitor their own malicious payloads.
    result = sys.call_tracing(target, (21,))
    print(f"  result: {result}")
    sys.settrace(None)


if __name__ == "__main__":
    print("[*] sys tracing hook demo (intentionally risky patterns)\n")
    demo_settrace()
    print()
    demo_setprofile()
    print()
    demo_call_tracing()

    print("\n[*] Safe alternative for profiling: use cProfile (scoped, explicit)")
    import cProfile
    import io
    import pstats

    pr = cProfile.Profile()
    pr.enable()
    sum(range(1000))
    pr.disable()
    s = io.StringIO()
    pstats.Stats(pr, stream=s).sort_stats("cumulative").print_stats(3)
    print("    cProfile output (scoped to a known block):")
    for line in s.getvalue().splitlines()[:5]:
        print(f"    {line}")