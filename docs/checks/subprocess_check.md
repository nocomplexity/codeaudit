# Subprocess Statement

Codeaudit checks the use of Subprocesses in a Python file.

Using the default Python library `subprocess` for Subprocess management is very powerfull.

:::{caution} 
When using the `subprocess` library the Python code can invoke an external executable. 
:::


Python `codeaudit` does not check on `Popen.communicate` This method cannot be directly used on a "foreign" process. It can only work on a launched by subprocess that is created by `Popen` in the same Python script. Popen.communicate() is a method of the Popen object. 

It is good to known that Python's `subprocess` module doesn't provide a mechanism to "attach" to standard I/O streams of an already running process. 

Note that when *old* subprocess functions are used, the severity is high. So avoid using the functions and migratie to `.run` for:
* subprocess.call


## More information

* https://docs.python.org/3/library/subprocess.html
