# Marhal statement

The use of the `marshal` can give security issues.

The marshal module is not intended to be secure against erroneous or maliciously constructed data. 
Never unmarshal data received from an untrusted or unauthenticated source.

:::{danger} 
Security concerns when using `marshal` are similar when using pickle, but even less safe. Use `marshal` only for internal use in python programs that are not to be used by others or are distributed. 
:::

:::{tip} 
When `marshal` is used , search for the `allow_code=True` parameter.

:::


When True, `marshal.load()` is permitted to load Python code objects (like those produced by compile()). If the marshalled data contains code objects and allow_code is False, a `ValueError` will be raised.


If an attacker can provide a marshalled file where allow_code is True, they can embed malicious Python code within that file. When your application calls marshal.load() on it, that malicious code becomes a Python code object in memory. If your application then proceeds to exec() or eval() that loaded object (or if it's implicitly executed as part of a larger structure), the attacker's code will run with the permissions of your application. This is a classic remote code execution (RCE) vulnerability.


## More information

* https://docs.python.org/3/library/marshal.html