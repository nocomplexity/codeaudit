# Built-in Functions

Some Python built-in functions can cause severe risks. 

The Python built-in functions:
* `eval`
* `exec` and
* `compile`
Should always be reviewed within the full context. By default use of this function is a **red** alert from a security perspective.


## Why check on `eval`
 
This function executes arbitrary code. Calling it with user-supplied input may lead to security vulnerabilities.

This function can also be used to execute arbitrary code objects (such as those created by compile()).

## Why Check on `exec`

This function executes arbitrary code. Calling it with user-supplied input may lead to security vulnerabilities.

## Why check on `compile`

It is possible to crash the Python interpreter with a sufficiently large/complex string when compiling to an AST object due to stack depth limitations in Python’s AST compiler.

## More info

* https://docs.python.org/3/library/functions.html#eval 

* https://docs.python.org/3/library/functions.html#exec

* https://docs.python.org/3/library/functions.html#compile