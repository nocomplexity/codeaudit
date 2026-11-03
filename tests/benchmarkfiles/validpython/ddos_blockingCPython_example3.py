# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0

# still can and will CPU Exhaustion, but will not be detected by SAST, since AST parsing will not time out. Only when code is executed things will break!

# Demonstrates Python's inability to parse extremely deeply nested parentheses.
# SAST is static, so SAST scanners will not detect this dynamic constructed type of DDOS attacks...

SAST_META = {
    "title": "Deeply Nested Parentheses Causing Resource Exhaustion and Parser Recursion via compile",
    "cwe_id": [400, 770, 674],   # 400 Uncontrolled Resource Consumption, 770 Allocation of Resources Without Limits or Throttling, 674 Uncontrolled Recursion
    "weakness": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
    "owasp": "A06:2025 - Insecure Design",
    "severity": "Critical",
    "cvss": 9.1,
    "impact": "High",
    "tags": ["nested-parentheses", "compile", "resource-exhaustion", "recursion-limit",
             "parser-dos", "memory-exhaustion", "denial-of-service", "python"],
}

N = 50_000000
expr = "(" * N + "1" + ")" * N

# Safe, no eval, no parser nesting limit
result = int(expr.replace("(", "").replace(")", ""))
print(f'Result: {result}')   # → 1

N = 50_000  # tens of thousands of nesting levels

expr = "(" * N + "1" + ")" * N

print(f"Expression length: {len(expr):,} characters")
print("Attempting to parse...")

try:
    compile(expr, "<string>", "eval") #this is detected
    print("Unexpectedly succeeded!")
except SyntaxError as e:
    print(f"Failed as expected: {e}")
