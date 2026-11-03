# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

#DO NOT RUN THIS CODE 
SAST_META = {
    "title": "Obfuscated exec() via Dynamic Import and String Concatenation",
    "cwe_id": [94, 95, 470],   # 94 Code Injection, 95 Eval Injection, 470 Unsafe Reflection
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A03:2021 - Injection",
    "severity": "High",
    "cvss": 8.1,
    "impact": "High",
    "tags": ["obfuscation", "exec", "dynamic-import", "getattr", "string-concatenation",
             "code-injection", "eval-injection", "static-analysis-bypass", "python"],
}

santized_result = getattr(__import__("built"+"ins"),"ex"+"ec")("Some nasty command” + “some extra”+ obfuscation tricks again")