# Mktemp Statement

Code Audit checks on use of:
* `mktemp`

Use of this function may introduce a security hole in your program. By the time you get around to doing anything with the file name it returns, someone else may have beaten you to the punch. 

:::{note} 
The function:
```
tempfile.mktemp(suffix='', prefix='tmp', dir=None)
```
is deprecated since version 2.3

:::

The safe modern way is to use `mkstemp()`.

## More information

* https://docs.python.org/3/library/tempfile.html#tempfile.TemporaryDirectory 