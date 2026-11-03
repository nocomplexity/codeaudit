# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


# sast_meta data
SAST_META = {
    "title": "Arbitrary Module Import via User-Controlled importlib.import_module",
    "cwe_id": [94, 470, 829],   # 94 Code Injection, 470 Unsafe Reflection, 829 Inclusion of Functionality from Untrusted Control Sphere
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A05:2025 - Injection",
    "severity": "Critical",
    "cvss": 9.8,
    "impact": "Critical",
    "tags": ["importlib", "dynamic-import", "user-input", "unsafe-reflection",
             "code-injection", "arbitrary-module-load", "rce", "python"],
}

import importlib

def reload_agent():
    """
    Dynamically reload the agent configuration module.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location("agent_config", "agent_config.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)


module = importlib.import_module("module_name")

# INSECURE: Directly importing user-supplied module name

user_input = input("Enter module name to load: ")
module = importlib.import_module(user_input)

# If user enters "os", they can now access system functions
# If user enters "subprocess", they can execute shell commands
module.system("rm -rf /")  # Potentially catastrophic