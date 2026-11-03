# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


# sast_meta data
SAST_META = {
    "title": "Path Traversal and Insecure Directory Creation from User Input",
    "cwe_id": [22, 732, 362],   # 22 Path Traversal, 732 Incorrect Permission Assignment, 362 Race Condition (TOCTOU)
    "weakness": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "owasp": "A01:2025 - Broken Access Control",
    "severity": "High",
    "cvss": 8.1,
    "impact": "High",
    "tags": ["os.mkdir", "os.makedirs", "path-traversal", "user-input",
             "insecure-permissions", "world-writable", "race-condition",
             "toctou", "python"],
}

import os

# INSECURE: Directly using user input to create a directory
user_input = input("Enter directory name to create: ")
path=user_input
# No input validation, no path sanitisation
os.mkdir(user_input)

# INSECURE: Overly permissive directory (world-writable)
os.makedirs("/tmp/app_cache", mode=0o777)

# INSECURE: Race condition pattern (check-then-act)
if not os.path.exists("/tmp/myapp/data"):
    os.makedirs("/tmp/myapp/data")

os.makedev(path)
os.mkfifo(path)
os.mknod(path)
os.makedirs(path, exist_ok=True)