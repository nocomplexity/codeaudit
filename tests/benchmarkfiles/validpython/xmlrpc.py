# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

# SAST Metadata
SAST_META = {
    "title": "Insecure XML-RPC Service Exposure",
    "cwe_id": [502, 611, 306],  # 502 deserialization of untrusted data (XML parsing),
                                # 611 improper restriction of XML external entity reference (XXE),
                                # 306 missing authentication for critical function
    "weakness": "Deserialization of Untrusted Data / Improper Restriction of XML External Entity Reference",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "severity": "High",
    "cvss": 8.1,
    "impact": "High",
    "tags": ["xmlrpc", "xmlrpc-client", "xmlrpc-server", "simplexmlrpcserver",
             "xxe", "deserialization", "unauthenticated-access", "xml-parsing",
             "remote-invoke", "python"],
}

#server code
from xmlrpc.server import SimpleXMLRPCServer

def is_even(n):
    return n % 2 == 0

# Create server, register function, and serve
server = SimpleXMLRPCServer(("localhost", 8000))
print("Listening on port 8000...")
server.register_function(is_even, "is_even")
server.serve_forever()

#client code
import xmlrpc.client

# Connect to the server and call the remote method
with xmlrpc.client.ServerProxy("http://localhost:8000/") as proxy:
    print("3 is even:", proxy.is_even(3))
    print("100 is even:", proxy.is_even(100))