# Handling warnings

Codeaudit captures warnings.

But:
:::{caution} 
Warnings are only presented on the CLI interface! 
:::

An example of a warning is:
```text
codeaudit overview ../codeaudit/tests
Error: ../codeaudit/tests/validationfiles/python2_file_willnotwork.py will be skipped due to syntax error while parsing into AST.

```
Warnings are raised when parsing code into the AST is not possible.

:::{admonition} Warnings are security relevant!
:class: note
Warnings written to `sys.stderr` by the `warnings` are often relevant from a security perspective. So take notice!
:::

Paying attention to warnings is a crucial part of a taken security seriously.  

## Background on warnings

Warnings in during scanning can have multiple causes: 

* **Deprecation Warnings:** Many warnings indicate that a function, module, or feature is deprecated. Deprecated features are often removed or changed in future Python versions. A reason for deprecated functions is sometimes known security vulnerabilities. For example, using an outdated hashing algorithm (like MD5 for security-sensitive purposes) might trigger a deprecation warning, and continuing to use it would be a security risk.

* **Misconfigurations or Insecure Defaults:** Sometimes, a warning might flag a configuration that is insecure by default or a common misconfiguration. While the warning itself isn't an exploit, ignoring it could leave your application vulnerable. For instance, a library might issue a warning if you're using it in a way that makes it susceptible to certain attacks (e.g., if you're not properly sanitizing inputs when using a function that executes shell commands).


* **Runtime Anomalies Indicating Potential Issues:** Some runtime warnings could indicate unexpected behavior that might be exploitable. For example, a `ResourceWarning` about an unclosed file handle might not be a direct security flaw, but in a resource-constrained environment or if an attacker could control file paths, it *could* contribute to a denial-of-service or information disclosure vulnerability.

* **Debugging and Forensics:** In a post-compromise scenario, warnings in `sys.stderr` can provide valuable clues about how an attacker might have exploited a vulnerability or what unusual code paths were executed. They are part of the overall diagnostic output of a program.




### More information

* https://docs.python.org/3/library/warnings.html