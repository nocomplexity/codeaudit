# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0

# still can and will CPU Exhaustion, but will not be detected by SAST, since AST parsing will not time out. Only when code is executed things will break!

# Demonstrates Python's inability to parse extremely deeply nested parentheses.
# SAST is static, so SAST scanners will not detect this dynamic constructed type of DDOS attacks...

# Example of Python script using the assert statement - which can lead to security issues!
# sast_
SAST_META = {
    "title": "Decompression of Potentially Untrusted Data Leading to Resource Exhaustion",
    "cwe_id": [400, 409],   # 400 Uncontrolled Resource Consumption, 409 Improper Handling of Highly Compressed Data (Data Amplification)
    "weakness": "Improper Handling of Highly Compressed Data (Data Amplification)",
    "owasp": "A06:2025 - Insecure Design",
    "severity": "High",
    "cvss": 7.5,
    "impact": "High",
    "tags": ["bz2", "decompression", "decompression-bomb", "resource-exhaustion",
             "data-amplification", "untrusted-data", "denial-of-service", "python"],
}

import bz2

# Open the compressed file in read text mode ('rt')
with bz2.open("malware_example.bz2", "rt") as f:
    # Read the entire content of the file
    read_data = f.read()

print(f"Content read from the file: '{read_data}'")

#now with the class function
with bz2.BZ2File("demo.bz2", mode='r') as f:
    content = f.read()

