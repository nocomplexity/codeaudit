# Information on checks

**Python Code Audit** has many implemented security checks based on possible security threats when using Python Standard Library (PSL) calls.

Checks are done to determine:
* **If** and
* **Where**

Python source code uses functions or classes that are a security weakness.

A security weakness is a flaw, design choice, or implementation issue that could potentially lead to a security problem — but isn’t necessarily exploitable by itself.

:::{admonition} **Review**, **remediate**, and **validate** all identified security weaknesses in the code!
:class: tip
Ensure that all reported **security findings** are fully addressed. The code must be thoroughly reviewed and corrected to eliminate weaknesses and prevent potential exploitation as **vulnerabilities**.

:::




The majority of validations is done using advanced AST parsing of Python files. Parsed code is **not** compiled or executed. This to prevent security issues when using this tool!

Due to using the AST for validations implemented constructs code that use Python Standard Library modules that can be in potential cause a security issue. Also when aliases are used constructs will be detected. Aliases in code are often not directly detected with a 'human' code review. Sometimes even on purpose!

To check if an imported function is used several cases of occurrence  will be detected. For e.g. `os.access`  call:
* import os
* import os as alias	
* from os import access	
* from os import access as x

So the following `clown` construct is detected, since **Python Code Audit** checks on use of the `system` method of the `os` module.
```python
from os import system as clown
clown('ls -la')
```

## Validations overview


In the following subsections detailed information on implemented security validations:
```{tableofcontents}
```

