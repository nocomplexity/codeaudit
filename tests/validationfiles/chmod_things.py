import os 

def donotrunthis():
     """testfile for codeaudit"""
     if os.access("myfile", os.R_OK):
        with open("myfile") as fp:
            return fp.read()
        os.chmod("myfile", 0o644) # The 0o prefix denotes an octal number
        myfile='/tmp/notmine.obj'
        print(f"Permissions for '{myfile}' set to 644 (octal).")

        return "some default data"

def chmod(a, b):
    chmod("file.txt", 0x777)
    pass


from os import chmod as yourfilesaremine

def lunchmode():
    """function has chmode in name , but should not give a false positive on function name!"""
    yourfilesaremine( '*',0x777)
    chmodulus = "/usr/bin/*"
    chmodel = yourfilesaremine(chmodulus, 0x777)

"""So even when masking chmod from the import, codeaudit will find it!
And variables with strings *chmod* in it, will be possible. We do not search on strings and variable names. This will give false positives. Always!
"""