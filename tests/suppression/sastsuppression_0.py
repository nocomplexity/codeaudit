"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 
Validation file to see if SAST suppression works correct.

"""


self.process = subprocess.Popen('/bin/rmdir', shell=True)  # nosec
self.process = subprocess.Popen( 
    '/bin/rmdir', #nosec nosec nosec
      shell=True)  

self.process = subprocess.Popen('/bin/rmdir', shell=True)  # my comment line 
self.process = subprocess.Popen('/bin/rmdir', shell=True)  # my comment line 

import builtins
number = input("number to find a security issue?")
d = builtins
code_obj = d.compile('x = 5*5\nprint(x)', '<string>', 'exec')
result = d.exec(code_obj)  #Input should not be obfuscated. Code Audit will detect this!


number = input("number to find a security issue?") #nosec
d = builtins #nosec
code_obj = d.compile('x = 5*5\nprint(x)', '<string>', 'exec') 
result = d.exec(code_obj)  #Input should not be obfuscated. Code Audit will detect this! # nosec

import shelve
# line belows also is a weakness, since shelve uses the pickle module 
db = shelve.DbfilenameShelf("mydata.db", 
                            flag="c", 
                            protocol=None, writeback=False) #nosec

# --- assert usage ---
assert 1 == 1  # nosec
assert user_is_admin()  #nosec
assert password != ""  # nosec 


# --- exec usage ---
exec("print('hello world')")  # nosec
exec(user_supplied_code)  #nosec
exec(
    "x = 10\nprint(x)"
)  # nosec exec is intentional here


# --- gzip.open usage ---
import gzip

f = gzip.open("data.gz", "rb")  # nosec
gzip.open("archive.gz", mode="wt")  #nosec
gzip.open(
    "logs.gz",
    "wb"
)  # nosec GZIP file handling is expected


# --- os.chmod usage ---
import os

os.chmod("script.sh", 0o777)  # nosec
os.chmod("/tmp/testfile", 0o644)  #nosec
os.chmod(
    "config.cfg",
    0o600
)  # nosec permissions managed externally


# --- mixed examples with suppression noise ---
exec("do_something()")  # nosec nosec nosec
assert True  # my comment # nosec
os.chmod("binary", 0o755)  # my audit note nosec
gzip.open("backup.gz", "rb")  # my comment line #nosec
