# Dynamic Import Statements

Using dynamic imports are a potential security issues.
Especially if you can not validate upfront what is imported.

Python Code Audit checks on:
* `__import__`: This builtin function SHOULD never be used anymore. This is an advanced function that is not needed in everyday Python programming. 
* `importlib.import_module` use. Using this function should be validated upfront.
* `importlib.util.spec_from_file_location`
* `importlib.util.module_from_spec`

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

* Using `importlib.util.spec_from_file_location()` in combination with `importlib.util.module_from_spec` can bypass the normal Python import mechanism and allow arbitrary Python files to be executed. 



## Mitigation

There is always a security risk when `importlib.import_module()` is used. 

Possible mitigations:
* **ALWAYS** use the Python Code Audit `modulescan` option for all modules within a file.
* Check and understand what will be imported and what security risks are involved. You **MUST** never trust that dynamic imports are safe. Most are not!
* Check if your Python program has or needs an API to download dynamic imports. 
* If you do not trust it: Call a security expert to help you! See the [sponsor](../sponsors) page for companies that could help you!


While `importlib.util.spec_from_file_location` is frequently seen in legacy plugin systems, it carries substantial security risks. Modern Python plugin architectures provide much safer mechanisms to prevent the execution of arbitrary files from untrusted locations.


## References

* https://docs.python.org/3/library/functions.html#import__ 
* [CVE-2026-40156](https://nvd.nist.gov/vuln/detail/CVE-2026-40156) and see all [details](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-2g3w-cpc4-chr4).
* [Python Security Handbook](https://nocomplexity.github.io/pythonsecurity/)