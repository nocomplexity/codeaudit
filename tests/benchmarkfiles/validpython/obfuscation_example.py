# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

SAST_META = {
    "title": "Obfuscated exec() Leading to Arbitrary Code Execution and Destructive File System Operation",
    "cwe_id": [94, 95, 470],   # 94 Code Injection, 95 Eval Injection, 470 Unsafe Reflection
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A05:2025 - Injection",
    "severity": "Critical",
    "cvss": 9.8,
    "impact": "Critical",
    "tags": ["obfuscation", "exec", "dynamic-import", "getattr", "string-concatenation",
             "code-injection", "arbitrary-code-execution", "rmtree", "destructive", "python"],
}

import shutil
santized_result = getattr(__import__("built"+"ins"),"ex"+"ec")('shutil.rmtree("/usr/home/jaap")') #The line is obfuscated access to builtins.exec whose payload can be dangerous.

