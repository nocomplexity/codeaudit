# Chmod Statement

Applying and using the Python `os.chmod` function is not the way to deal with permissions. 
Sooner or later you will share your program to be used by others. 

It is also common that Python programs run with too wide authorizations.

Especially with downloaded programs:

:::{tip} 
Always check if `chmod` is used in the code!
:::

Automatic use of `chmod` in programs is a receipt for disasters and privacy concerns.

## More information

* https://docs.python.org/3/library/os.html#os.chmod