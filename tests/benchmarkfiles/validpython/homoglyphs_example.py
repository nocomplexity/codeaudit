# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

SAST_META = {
    "title": "Homoglyph Obfuscation of exec() to Evade Detection",
    "cwe_id": [1007, 94],   # 1007 Insufficient Visual Distinction of Homoglyphs, 94 Improper Control of Generation of Code ('Code Injection')
    "weakness": "Insufficient Visual Distinction of Homoglyphs Presented to User",
    "owasp": "A03:2021 - Injection",
    "severity": "High",
    "cvss": 8.1,
    "impact": "High",
    "tags": ["homoglyph", "confusable", "unicode", "obfuscation", "exec",
             "code-injection", "evasion", "static-analysis-bypass", "python"],
}

ℯ𝓍ℯ𝒸("print(2 + 2)")  #Confusable homoglyphs

ℯ𝓍ℯ𝒸("import os; os.system('ls')") # The string is not detected, only if full AST string searching is used or another method.