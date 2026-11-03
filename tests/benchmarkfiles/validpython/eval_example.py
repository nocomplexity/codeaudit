# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


# sast_meta data
SAST_META = {
    "title": "Arbitrary Code Execution via eval and Obfuscated Access Patterns",
    "cwe_id": [94, 95, 470],   # 94 Code Injection, 95 Eval Injection, 470 Unsafe Reflection
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A05:2025 - Injection",
    "severity": "Critical",
    "cvss": 9.8,
    "impact": "Critical",
    "tags": ["eval", "code-injection", "eval-injection", "obfuscation",
             "__builtins__", "__import__", "arbitrary-code-execution", "python"],
}

class Test(object):
    def eval(self):
        print("hi")
    def foo(self):
        self.eval()

Test().eval() #Still flagged! 
eval("2 + 2")

eval("os.system('rm -rf /')") # flag 

__builtins__.eval("ls")  # flag   due to eval statement

nasty  = __import__("builtins").eval     # flag due to __import__  and for eval!
