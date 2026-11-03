# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

#Based on https://nvd.nist.gov/vuln/detail/cve-2025-6069 
# SAST scanner will not detect this, only some taint rules will.
# Mitigation is partly within CPython, but process time-outs are real when running below example

SAST_META = {
    "title": "Regular Expression Denial of Service (ReDoS) via Nested Quantifiers",
    "cwe_id": [1333, 400],   # 1333 Inefficient Regular Expression Complexity, 400 Uncontrolled Resource Consumption
    "weakness": "Inefficient Regular Expression Complexity",
    "owasp": "A06:2025 - Insecure Design",
    "severity": "High",
    "cvss": 7.5,
    "impact": "High",
    "tags": ["redos", "regex", "catastrophic-backtracking", "nested-quantifiers",
             "resource-exhaustion", "denial-of-service", "python"],
}


import re

def vulnerable_parse(input_string):
    """
    Simulated vulnerable parsing function.
    This regular expression contains a nested quantifier (a+)+,
    which triggers catastrophic backtracking when matching specific non-matching strings,
    causing execution time to grow quadratically or exponentially.
    """
    # Dangerous regular expression: nested quantifiers can cause catastrophic backtracking
    pattern = re.compile(r'^(a+)+$')
    
    # If the input is a long string containing many 'a's followed by an 'X' (which causes match failure),
    # the engine will attempt all possible combinations, consuming massive CPU time.
    if pattern.match(input_string):
        return True
    return False

# Attack payload example (in actual attacks, the length may be larger)
# Malicious input: 'a' * 30 + 'X'
# This will cause the regular expression engine to fall into a "backtracking hell"
malicious_input = "a" * 30 + "X"

# Simulate processing user input
print("Start processing input...")
# In actual scenarios, this line may cause the server to freeze for several seconds or even minutes.
result = vulnerable_parse(malicious_input)
print(f"Result: {result}")