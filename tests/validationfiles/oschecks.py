
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

import os
os.popen('malware -all')
bytes_written = os.write(fd, data_to_write)
bytes_written2 = os.writev(fd, buffers)

pid_zero = os.forkpty() 
pid = os.fork()

from os import fork as cannothurt

#DO NOT RUN THIS CODE!
while True:
    cannothurt()  # Creates a new child process
