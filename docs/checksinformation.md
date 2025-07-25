# Overview of checks

Python `Codeaudit` has many implemented checks.

Checks are done to determine:
* If and
* Where
Python source code uses functions or classes that can be in potential lead to security issues.

The majority of validations is done using advanced AST parsing of Python files. Parsed code is **not** compiled or executed. This to prevent security issues when using this tool!

Due to using the AST for validations implemented constructs code that use Python Standard Library modules that can be in potential cause a security issue. Also when aliases are used constructs will be detected. Aliases in code are often not directly detected with a 'human' code review. Sometimes even on purpose!

To check if an imported function is used several cases of occurrence  will be detected. For e.g. `os.access`  call:
* import os
* import os as alias	
* from os import access	
* from os import access as x

So the following `clown` construct is detected, since `codeaudit` checks on use of the `system` method of the `os` module.
```python
from os import system as clown
clown('ls -la')
```

## Validations overview

* Check on assert
* Check for chmod
* Directory creation
* OS System call - Fork a child process
* Check on eval usage
* Check on input statement
* Exception Handling
* Continue statement
* Built-in Functions: Check for exec usage.
* Built-in Functions: Check on compile usage.
* Hash Check - md5
* Hash Check - sha1
* Logging - configuration
* Pickle use
* OS - direct calls
* OS - execl
* OS - execle
* OS - execlp
* OS - execlpe
* OS - execv
* OS - execve
* OS - execvp
* OS - execvpe
* OS - popen
* OS Access
* OS Interfaces
* Marshal
* Subprocesses - call
* Subprocesses - check_call
* Subprocesses - Popen
* Subprocesses - run
* Tarfile use
* Encodings use
* XML - client use
* XML - server use
* Random numbers generation module
* Shelve module use
* Multiprocessing
* Zipfile use
* shutil se
* HTTP servers: Check on usage.

In the following subsections more detailed information validations:
```{tableofcontents}
```

