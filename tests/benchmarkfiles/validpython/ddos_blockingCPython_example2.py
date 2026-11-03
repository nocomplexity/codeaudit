# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

#still can and will CPU Exhaustion, but will not be detected by SAST, since AST parsing will not time out. Only when code is executed things will break!

SAST_META = {
    "title": "Deeply Nested Parentheses Causing Resource Exhaustion via eval",
    "cwe_id": [400, 770, 674],   # 400 Uncontrolled Resource Consumption, 770 Allocation of Resources Without Limits or Throttling, 674 Uncontrolled Recursion
    "weakness": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
    "owasp": "A06:2025 - Insecure Design",
    "severity": "Critical",
    "cvss": 9.1,
    "impact": "High",
    "tags": ["nested-parentheses", "eval", "resource-exhaustion", "recursion-limit",
             "parser-dos", "memory-exhaustion", "denial-of-service", "python"],
}

def make_code_line(expression, num_parens=1):
    """Takes an expression input and outputs Python source code as a string."""
    opening = "(" * num_parens
    closing = ")" * num_parens
    
    # Return a valid line of Python source code
    return f"{opening}{expression}{closing}"

generated_code = make_code_line("3 + 4", num_parens=1000000000)
#print(generated_code)
print(eval(generated_code))