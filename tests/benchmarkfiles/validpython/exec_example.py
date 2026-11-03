# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


# sast_meta data
SAST_META = {
    "title": "Arbitrary Code Execution via exec of User Input and File Contents",
    "cwe_id": [94, 95],   # 94 Improper Control of Generation of Code ('Code Injection'), 95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A05:2025 - Injection",
    "severity": "Critical",
    "cvss": 9.8,
    "impact": "Critical",
    "tags": ["exec", "code-injection", "eval-injection", "user-input",
             "file-execution", "arbitrary-code-execution", "alias", "python"],
}

exec("4*23")

exec("nasty command , retrieved using a dynamic import")

func_name = input("Enter function to run: ")
exec(f"{func_name}()")

secure_function = exec
with open(path) as f:
    secure_function(f.read())   # <-- arbitrary Python executes with full privileges
    