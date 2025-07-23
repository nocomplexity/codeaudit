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
    