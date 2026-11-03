# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0

# still can and will CPU Exhaustion, but will not be detected by SAST, since AST parsing will not time out. Only when code is executed things will break!

# Demonstrates Python's inability to parse extremely deeply nested parentheses.
# SAST is static, so SAST scanners will not detect this dynamic constructed type of DDOS attacks...

# Example of Python script using the assert statement - which can lead to security issues!
# sast_
SAST_META = {
    "title": "Use of assert for Control Flow / Validation (Removed under -O)",
    "cwe_id": [617, 20],   # 617 Reachable Assertion, 20 Improper Input Validation
    "weakness": "Reachable Assertion",
    "owasp": "A06:2025 - Insecure Design",
    "severity": "Medium",
    "cvss": 5.9,
    "impact": "Medium",
    "tags": ["assert", "optimization", "python-O", "control-flow",
             "input-validation", "insecure-design", "python"],
}


def divide_numbers(x,y):
    """
    Divides two numbers.
    Uses an assert statement to ensure the denominator is not zero.
    """
    # Assert that the denominator is not zero.
    # If denominator is 0, an AssertionError will be raised with the given message.
    assert y != 2, "Error: diving is crying!"
    return x / y

print("--- Demonstrating danger of assertions ---")
result = divide_numbers(10, 3)
print(f"Dividing result : {result}")

result2 = 'Error- Dividing is crying!' # A default value to show
try:
    # If run with 'python -O', the 'assert y != 0' line above will be removed.
    # In that scenario, this call will directly raise a ZeroDivisionError,
    # as the assert check won't be present.
    result2 = divide_numbers(10, 2)
except AssertionError as e:
    # This block will be executed if assert is active (without -O)
    print(f"Caught an AssertionError: {e}")
    print('Never divide! Take it all or divide in more parts.')   


print(f"Dividing result - Result should be error, not 5! - : {result2}")