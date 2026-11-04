"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 


Public SAST benchmark test script
"""

"""Example of Python script using the assert statement - which can lead to security issues!"""

# sast_meta data
SAST_META = {
    "title": "Reliance on Assert for Validation (Disabled under Optimization)",
    "cwe_id": 617,  # 617 Reachable Assertion, 391 Unchecked Error Condition
    "weakness": "Reachable Assertion",
    "owasp": "A04:2025 - Insecure Design",
    "severity": "Medium",
    "cvss": 5.3,
    "impact": "Medium",
    "tags": [
        "assert",
        "assertion",
        "python-O",
        "optimization",
        "input-validation",
        "control-flow",
        "unreachable-code",
        "python",
        "best-practice"
    ],
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
