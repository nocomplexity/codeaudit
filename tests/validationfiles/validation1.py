"""File 1 - not real Python file
result should be 
lines: 
"""

from os import access as check_access 
import os 
if check_access("file.txt", os.R_OK):
    print("Accessible")

eval("2 + 2")


if os.access("myfile", os.R_OK):
    with open("myfile") as fp:
        return fp.read()
return "some default data"

text = "Hello".lower()

