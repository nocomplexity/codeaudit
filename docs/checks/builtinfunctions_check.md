# Built-in Functions

Some Python built-in functions can cause severe risks. 

The Python built-in functions:
* `eval`
* `exec` and
* `compile`
Should always be reviewed within the full context. By default use of this function is a **red** alert from a security perspective.


## Why check on `eval`

:::{admonition} Security risk
:class: danger
`eval()` can execute arbitrary Python code. 

If the input is user-controlled or from an untrusted source, this can be exploited.
:::

So calling `eval` with user-supplied input may lead to security vulnerabilities.

The `eval` function can also be used to execute arbitrary code objects (such as those created by `compile()`). 

Most Python programs should not need to use this built-in function.


## Why Check on `exec`

This function executes arbitrary code. Calling it with user-supplied input may lead to security vulnerabilities.

## Why check on `compile`

It is possible to crash the Python interpreter with a sufficiently large/complex string when compiling to an AST object due to stack depth limitations in Python’s AST compiler.

## More info

* https://docs.python.org/3/library/functions.html#eval 

* https://docs.python.org/3/library/functions.html#exec

* https://docs.python.org/3/library/functions.html#compile