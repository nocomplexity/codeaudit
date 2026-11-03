# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


# sast_meta data
SAST_META = {
    "title": "Socket Bound to All Interfaces (0.0.0.0 / ::)",
    "cwe_id": [668],   # 668 Exposure of Resource to Wrong Sphere
    "weakness": "Exposure of Resource to Wrong Sphere",
    "owasp": "A02:2025 - Security Misconfiguration",
    "severity": "Medium",
    "cvss": 5.3,
    "impact": "Medium",
    "tags": ["socket", "bind", "0.0.0.0", "all-interfaces",
             "network-exposure", "insecure-configuration", "python"],
}

import socket

addr = ("", 8080)

if socket.has_dualstack_ipv6():
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind(addr)
s.listen()