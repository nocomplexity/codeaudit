"""File 2 - not real Python file
result should be 
lines: 
"""
import os
from os import access as x 

if x("file.txt", os.R_OK):
    print("Accessible")
eval("2 + 2")

if x("myfile", os.R_OK):
    with open("myfile") as fp:
        return fp.read()
return "some default data"

text = "Hello".lower()

