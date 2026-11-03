# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0

# sast_meta data
SAST_META = {
    "title": "Use of compile() as a Code Injection Primitive",
    "cwe_id": [94, 95],   # 94 Improper Control of Generation of Code ('Code Injection'), 95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A05:2025 - Injection",
    "severity": "High",
    "cvss": 8.1,
    "impact": "High",
    "tags": ["compile", "code-injection", "eval-injection", "dynamic-code",
             "dangerous-api", "python"],
}

compile('nasty-string' ,'malware.bin',mode=single, flags=0, dont_inherit=False, optimize=-1)