"""Sample file for module check"""

import csv
import os
import random

import linkaudit  # has no data in OSV DB
import pandas  # has some minor data in OSV
import requests  # has lots of OSV data

# import numpy #has lots of OSV data! (a lot!!)


def donothing():
    print("no way!")
    os.chmod(
        "ooooooooooooono.txt", 0x777
    )  # this will give an alert on codeaudit filescan!
