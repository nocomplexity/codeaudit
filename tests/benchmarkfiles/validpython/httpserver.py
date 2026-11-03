# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


# sast_meta data
SAST_META = {
    "title": "Insecure HTTP Server Binding to All Interfaces and Serving Filesystem",
    "cwe_id": [200, 668],   # 200 Exposure of Sensitive Information, 668 Exposure of Resource to Wrong Sphere
    "weakness": "Exposure of Sensitive Information to an Unauthorized Actor",
    "owasp": "A02:2025 - Security Misconfiguration",
    "severity": "High",
    "cvss": 7.5,
    "impact": "High",
    "tags": ["http-server", "simplehttprequesthandler", "bind-all-interfaces",
             "0.0.0.0", "information-disclosure", "filesystem-exposure",
             "insecure-configuration", "python"],
}


from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

# This serves the current directory over HTTP on all interfaces
# This is extremely dangerous and should never be used
server_address = ('0.0.0.0', 8000)
httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)

# This will serve all files in the current directory
# Potentially exposing source code, configuration files, and secrets
print("Serving files from:", os.getcwd())
print("WARNING: This server is insecure and should only be used for local testing")
httpd.serve_forever()

from http.server import BaseHTTPRequestHandler, HTTPServer

# Define a custom request handler
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    """
    A simple HTTP request handler that responds to GET requests.
    """
    def do_GET(self):
        """
        Handles GET requests by sending a 200 OK response
        and "Hello, World!" as the body.
        """
        self.send_response(200)  # Send HTTP status code 200 (OK)
        self.send_header('Content-type', 'text/html') # Set the content type header
        self.end_headers() # End the headers section

        # The message to send back to the client
        message = "Hello, World!"
        # Write the message to the response body, encoded as bytes
        self.wfile.write(bytes(message, "utf8"))

# The function to run the HTTP server
def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler):
    """
    Starts an HTTP server on port 8000.

    Args:
        server_class: The server class to use (default: HTTPServer).
        handler_class: The handler class to use (default: BaseHTTPRequestHandler).
    """
    server_address = ('', 8000) # Server will listen on all available interfaces on port 8000
    httpd = server_class(server_address, handler_class) # Create an instance of the HTTP server
    print(f"Starting httpd server on port {server_address[1]}...")
    httpd.serve_forever() # Start the server and keep it running indefinitely
    