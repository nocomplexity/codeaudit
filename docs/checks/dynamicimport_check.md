# Dynamic Import Statements

Using dynamic imports are a potential security issues.
Especially if you can not validate upfront what is imported.

Python Code Audit checks on:
* `__import__`: This builtin function SHOULD never be used anymore. This is an advanced function that is not needed in everyday Python programming. 
* `importlib.import_module` use. Using this function should be validated upfront.


Using the dynamic imports can be a potential security issue, especially when the module name comes from an untrusted source. Often modules are fetches from internet or are imported by cleaver user input constructs in the code. But an attacker could also import the `os` module and then find a way to call functions to run commands on the system. 

:::{caution} 
Allowing dynamically module imports makes it easy to execute arbitrary code.
:::

:::{tip} 
If the Python code or package really must use dynamic module input:

Use:
`importlib.import_module()` 
This offers a better way to handle dynamic imports. Avoid using `__import__`.
:::

* `importlib.import_module()` is part of the standard library's importlib module, which is the modern way to interact with Python's import system programmatically. Its name clearly indicates its purpose, unlike `__import__()`, which looks like a "magic method" and is often a last resort or still found in old Python programs.

* Using `importlib.import_module()` keeps dynamic import logic contained within the `importlib module`, which is maintained by the core Python developers. This is from a security point of view  preferred over directly using the low-level built-in function `__import__`.

## Mitigation

There is always a security risk when `importlib.import_module()` is used. 

Possible mitigations:
* **ALWAYS** use the Python Code Audit `modulescan` option for all modules within a file.
* Check and understand what will be imported and what security risks are involved. You **MUST** never trust that dynamic imports are safe. Most are not!
* Check if your Python program has or needs an API to download dynamic imports. 
* If you do not trust it: Call a security expert to help you! See the [sponsor](../sponsors) page for companies that could help you!


## References

* https://docs.python.org/3/library/functions.html#import__ 