# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

SAST_META = {
    "title": "Obfuscated compile()/exec() via builtins Alias",
    "cwe_id": [94, 95, 470],   # 94 Code Injection, 95 Eval Injection, 470 Unsafe Reflection
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A05:2025 - Injection",
    "severity": "High",
    "cvss": 8.1,
    "impact": "High",
    "tags": ["obfuscation", "compile", "exec", "builtins", "alias",
             "code-injection", "dynamic-code", "static-analysis-bypass", "python"],
}

import builtins
d = builtins
code_obj = d.compile('x = 5*5\nprint(x)', '<string>', 'exec')
result = d.exec(code_obj)  #obfuscated 
print(result)

