"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 


Public API functions for Python Code Audit aka codeaudit on pypi.org
"""


import gzip
import zlib
import tarfile
import json
import tempfile

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from codeaudit import __version__

NOCX_HEADERS = {
    "user-agent": f"Python Code Audit /{__version__} (https://github.com/nocomplexity/codeaudit)",
    "Accept": "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
    "Accept-Encoding": "gzip, deflate,br",
    "Connection": "keep-alive",  
    "Upgrade-Insecure-Requests": "1",  
}


def get_pypi_package_info(package_name):
    """JSON response, needed to get download URL of sdist"""
    url = f"https://pypi.org/pypi/{package_name}/json"

    try:
        with urlopen(url) as response:
            return json.load(response)
    except HTTPError:        #When urlopen receives a 4xx (client error) or 5xx (server error) status code, it does not return the response object; instead, it immediately raises an exception called urllib.error.HTTPError. If a package is not found a 40x is send with json response {"message": "Not Found"}, I keep handling errors simple
        return False # No package with this name found on pypi.org!
    except URLError as e:
        print(f"Network error: {e}")
    return None

def get_pypi_download_info(package_name):
    """Retrieves the sdist download URL
    Using the PyPI JSON API to get the sdist download URL (https://docs.pypi.org/api/json/)
    Note JSON API result is a nested dict with all release info published, so finding the correct sdist download URL needs logic.
    """
    if get_pypi_package_info(package_name) :
        data = get_pypi_package_info(package_name)   
        releases_dict = data['releases']
        # Convert the key-value pairs (items) into a list and get the last one
        last_item = list(releases_dict.items())[-1] #last_item is a Python tuple
        sdist_download_url = find_download_url(last_item,'source') # We want the download URL of the source, so *.tar.gz file
        release_info = last_item[0] 
        pypi_package_info= { "download_url" : sdist_download_url ,
                            "release" : release_info}
        return pypi_package_info
    else:
        #package does not exist
        return False

def find_download_url(data, source):
    """
    Given the PyPI release tuple and a python_version string,
    return the URL of the first matching item.
    """    
    items = data[1] # Access the list of items directly via index 1 , data is a tuple    

    for item in items:
        if item.get("python_version") == source:
            return item.get("url")

    return None  # if no match found`


def get_package_source(url, nocxheaders=NOCX_HEADERS, nocxtimeout=10):
    """Retrieves a package source and extract so SAST scanning can be applied
    Make sure to cleanup the temporary dir!! Using e.g. `tmp_handle.cleanup()`  # deletes everything
    """
    try:
        request = Request(url, headers=nocxheaders or {})
        with urlopen(request, timeout=nocxtimeout) as response:
            content = response.read()
            content_encoding = response.headers.get("Content-Encoding")
            if content_encoding == "gzip":
                content = gzip.decompress(content)
            elif content_encoding == "deflate":
                content = zlib.decompress(content, -zlib.MAX_WBITS)
            elif content_encoding not in [None]:
                raise ValueError(f"Unexpected content encoding: {content_encoding}")

        # This directory will auto-delete when the context block exits
        tmpdir_obj = tempfile.TemporaryDirectory(prefix="codeaudit_")
        temp_dir = tmpdir_obj.name

        tar_path = f"{temp_dir}/package.tar.gz"
        with open(tar_path, "wb") as f:
            f.write(content)

        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(path=temp_dir,filter='data')  #Possible risks are mitigated as far as possible, see architecture notes.

        return temp_dir, tmpdir_obj  # return both so caller controls lifetime

    except Exception as e:
        print(e)