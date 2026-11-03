# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0

# sast meta data

SAST_META = {
    "title": "Base64-Obfuscated Payload Executed via exec()",
    "cwe_id": [94, 95],   # 94 Improper Control of Generation of Code ('Code Injection'), 95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A05:2025 - Injection",
    "severity": "Critical",
    "cvss": 9.8,
    "impact": "Critical",
    "tags": ["base64", "obfuscation", "exec", "code-injection", "malware-pattern",
             "payload-decoding", "static-analysis-bypass", "python"],
}

import base64

payload = b"import os; os.system('malicious command')"
encoded_b64 = base64.b64encode(payload) #1


# Encoding (attacker side)
encoded_b64 = base64.b64encode(payload) #2

# Decoding patterns (common in malware)
decoded1 = base64.b64decode(encoded_b64)  # Most common #3
decoded2 = base64.z85decode(base64.b85encode(payload))  # Less common #4

safe_string=b'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ21hbGljaW91cyBjb21tYW5kJyk='

# Decoding patterns - still common in Python malware
b64 = base64.b64decode #5
exec(b64(safe_string))  #6