"Test file with all shit inserted"

def divide(a, b):
    # Assert that the divisor 'b' is not zero.
    # If 'b' is 0, an AssertionError will be raised with the given message.
    assert b != 0, "Cannot divide by zero!"
    return a / b

# --- Example Usage ---

# This call will work correctly because b is not zero.
try:
    result1 = divide(10, 2)
    print(f"10 divided by 2 is: {result1}")
except AssertionError as e:
    print(f"Error: {e}")

print("-" * 20)

# This call will raise an AssertionError because b is zero.
try:
    result2 = divide(5, 0)
    print(f"5 divided by 0 is: {result2}")
except AssertionError as e:
    print(f"Error: {e}")

print("-" * 20)
exec("4*23") ; exec("4*23")

import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 31137))
s.bind(('192.168.0.1', 8080))

# danger_string = "Maikel"
# print(danger_string)


# Another assertion example outside a function
x = 10
# Assert that x is greater than 5.
assert x > 5, "x should be greater than 5"
print(f"Assertion passed: x ({x}) is greater than 5.")
try:
  do_some_stuff()
except ZeroDivisionError:
  pass

while keep_going:
  try:
    do_some_stuff()
  except ZeroDivisionError:
    continue  #bad security practice - strange things can happen without catching and logging
  


import hashlib 

def calculate_md5_hash(input_string):
  """
  Calculates the MD5 hash of a given string.

  Args:
    input_string: The string to be hashed.

  Returns:
    A hexadecimal string representing the MD5 hash.
  """
  # Encode the input string to bytes, as hashlib functions require bytes
  encoded_string = input_string.encode('utf-8')

  # Create an MD5 hash object
  md5_hash_object = hashlib.md5()
  sha1_hash_object = hashlib.sha1()


  # Update the hash object with the encoded string
  md5_hash_object.update(encoded_string)

  # Get the hexadecimal representation of the hash
  hex_digest = md5_hash_object.hexdigest()

  return hex_digest


from hashlib import sha1 as tooweak

def calculate_hash(input_string):
  """
  Calculates the MD5 hash of a given string.

  Args:
    input_string: The string to be hashed.

  Returns:
    A hexadecimal string representing the MD5 hash.
  """
  # Encode the input string to bytes, as hashlib functions require bytes
  encoded_string = input_string.encode('utf-8')

  # Create an MD5 hash object
  sha1_hash_object = tooweak()

  # Update the hash object with the encoded string
  sha1_hash_object.update(encoded_string)

  # Get the hexadecimal representation of the hash
  hex_digest = sha1_hash_object.hexdigest()

  return hex_digest


from os import access as check_access 
import os 
def nogood():
    if check_access("file.txt", os.R_OK):
        print("Accessible")

    eval("2 + 2")
    exec("4*23")


    if os.access("myfile", os.R_OK):
        with open("myfile") as fp:
            return fp.read()
    os.chmod("myfile", 0o644) # The 0o prefix denotes an octal number
    print(f"Permissions for '{myfile}' set to 644 (octal).")

    return "some default data"

def divide(a, b):
    """
    Divide a by b, handling ZeroDivisionError explicitly and
    demonstrating other parts of the try‑except ladder.
    """
    try:
        result = a / b                       # May raise ZeroDivisionError
    except ZeroDivisionError:
        print("❌ Can't divide by zero!")
        result = None                        # handle and recover
    except Exception as exc:                 # catches *any* other error
        # In real code, consider logging exc instead of pass
        pass                                 # swallow the error (not recommended)
        result = None
    else:
        # Runs only if no exception was raised in the try block
        print("✅ Division succeeded.")
    finally:
        # Always runs, whether an exception occurred or not
        print("🔚 Cleaning up—`finally` block executed.")
    return result

from os import system as clown
clown('ls -la')

#<LOGGING>
import os
os.popen('malware -all')
bytes_written = os.write(fd, data_to_write)
bytes_written2 = os.writev(fd, buffers)

import logging.config 
logging.config.listen(port=DEFAULT_LOGGING_CONFIG_PORT, verify=None) 


logging.config.fileConfig(fname, defaults=None, disable_existing_loggers=True, encoding=None)
#<END LOGGING checks>

#tarfile extractall is not secure by default
import tarfile

def extract_tar_gz(file_path, extract_path):
    with tarfile.open(file_path, 'r:gz') as tar:
        tar.extractall(path=extract_path)

def extract_tar_gz(file_path, extract_path):
    with tarfile.open(file_path, 'r:gz') as donot:
        donot.extractall(path=extract_path)

def func():
    with tarfile.open('archive.tar', 'r') as tf:
        # Extract a specific file (replace 'file.txt' with actual member name)
        tf.extract('file.txt')         
        # Extract all files
        tf.extractall()


class MyExtractor:
    def extractall(self, path):
        print(f"Extracting files to: {path}")

extractor = MyExtractor()
extractor.extractall("/some/directory")

class MyAcess:
    def access(self, path):
        print(f"Check on acces use ")

own_access = MyAcess()
own_access.access("wortel")

import pandas as pd
import linkaudit 

from xmlrpc.server import SimpleXMLRPCServer

def is_even(n):
    return n % 2 == 0

server = SimpleXMLRPCServer(("localhost", 8000))
print("Listening on port 8000...")
server.register_function(is_even, "is_even")
server.serve_forever()

import xmlrpc.client

with xmlrpc.client.ServerProxy("http://localhost:8000/") as proxy:
    print("3 is even: %s" % str(proxy.is_even(3)))
    print("100 is even: %s" % str(proxy.is_even(100)))

import xmlrpc.server 

pid = os.fork()

pid_zero = os.forkpty() 
pid = os.fork()

from os import fork as cannothurt

#DO NOT RUN THIS CODE!
while True and nobreak:
    cannothurt()  # Creates a new child process


compile('nasty-string' ,'malware.bin',mode=single, flags=0, dont_inherit=False, optimize=-1)

import base64
encoded = base64.b64encode(b'data to be encoded')
data = base64.b64decode(encoded)

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



import multiprocessing
import time

def sender_process(connection, message):
    """
    This function runs in a separate process and sends a message
    through the provided Connection object.
    """
    print(f"Sender process: Sending '{message}'")
    connection.send(message) # Send the message through the connection
    connection.close() # Close the connection after sending
    print("Sender process: Message sent and connection closed.")

def receiver_process(connection):
    """
    This function runs in a separate process and receives data
    using the Connection.recv() method.
    """
    print("Receiver process: Waiting to receive data...")
    # Receive data from the connection.
    # This call blocks until data is available.
    received_data = connection.recv()
    print(f"Receiver process: Received '{received_data}'")
    connection.close() # Close the connection after receiving
    print("Receiver process: Connection closed.")

from multiprocessing import Process, Pipe

def f(conn):
    conn.send([42, None, 'hello'])
    conn.close()    
    print(parent_conn.recv())   # prints "[42, None, 'hello']"
    
import pickle
pickle.loads(b"cos\nsystem\n(S'echo hello world'\ntR.")

def donotdothis():
    with open('data.pickle', 'rb') as f:
        data = pickle.load(f)

from pickle import loads as importmalware

importmalware('mysafefile.txt')

import random

def generate_random_float():
  """
  Generates a random floating-point number between 0.0 (inclusive) and 1.0 (exclusive).

  The random.random() function from Python's built-in 'random' module is used
  to produce this number.

  Returns:
    float: A random float between 0.0 and 1.0.
  """
  random.seed(23)
  random_number = random.random()
  return random_number

import shelve
with shelve.open('spam') as db:
    db['eggs'] = 'eggs'

import zipfile
import os

def insecure_extract(zip_path, extract_to_dir):
    """
    INSECURE: This function is vulnerable to the Zip Slip attack.
    It extracts all files from a zip archive without validating their paths.
    """
    print(f"--- INSECURE EXTRACTION of {zip_path} to {extract_to_dir} ---")
    os.makedirs(extract_to_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # This line is the vulnerability: it extracts directly without path validation.
        zip_ref.extractall(extract_to_dir)
    print("Extraction attempted (might be insecure).")


with ZipFile('spam.zip') as myzip:
    with myzip.open('eggs.txt') as myfile:
        print(myfile.read())

import shutil
shutil.unpack_archive("example.zip", "extracted_files", format="zip", filter="data")

from shutil import copy as stealmydata 
stealmydata("source_file.txt", "backup/source_file.txt", follow_symlinks=True)


def load_marshalled_data(filepath: str, allow_code: bool = False):
    """
    Loads data from a marshalled file using marshal.load().

    WARNING: Using allow_code=True with untrusted data is a severe security risk
    as it can execute arbitrary code. Only set allow_code=True if you
    absolutely trust the source of the marshalled file.
   
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Error: File not found at '{filepath}'")
     
    nastyobjects = marshal.loads('/tmp/plantedmalware.obj', allow_code=True)
    print(nastyobjects)

    try:
        with open(filepath, 'rb') as f:
            # The allow_code parameter is passed directly to marshal.load()
            loaded_object = marshal.load(f, allow_code=allow_code)
        return loaded_object
    except ValueError as e:
        print(f"Error loading marshalled data: {e}. "
              f"This might be due to 'allow_code=False' and the file containing code objects.", file=sys.stderr)
        raise
    except EOFError:
        print(f"Error: File '{filepath}' is empty or truncated.", file=sys.stderr)
        raise
    except Exception as e:
        print(f"An unexpected error occurred while loading '{filepath}': {e}", file=sys.stderr)
        raise

"""checking catching of sys things that are dangerous in normal programs"""
import sys 

def my_func(x, y):
    print("Inside my_func")
    result = x + y
    print(f"Result is {result}")
    return result

def run_with_profile():
    sys.setprofile(profile_func)
    result = my_func(5, 7)
    sys.setprofile(None)  # Turn off profiling
    print(f"Result: {result}")

def run_with_trace2():
    sys.settrace(trace_func)
    my_func(2, 3)
    sys.settrace(None)  # Disable tracing

import tempfile

temp_filename = tempfile.mktemp()
