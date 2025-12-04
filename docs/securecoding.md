# Secure Coding Guidelines

Security breaches that are possible when running untrusted Python programs are real.  

This checklist is created for anyone who wants to create Python programs that are [**secure by design**](https://nocomplexity.com/documents/securitybydesign/intro.html).

Programming in Python is fun, but when you create programs for others, you **SHOULD NOT** introduce security weaknesses.  

The key words **“MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”, “SHOULD NOT”, “RECOMMENDED”, “MAY”,** and **“OPTIONAL”** in this document are to be interpreted as described in [RFC 2119](http://tools.ietf.org/html/rfc2119).


## Things to Do

- **Input Validation:**  
  All user input **MUST** be validated for type, size, and format, and **MUST** be sanitised before use.

+++

- **Static Security Analysis:**  
  A Static Application Security Test (**SAST**) **MUST** be performed before releasing the program.  
  To minimize effort, it is **RECOMMENDED** to perform SAST automatically in the CI/CD workflow.  
  The preferred SAST tool for Python is **[Python Code Audit](https://github.com/nocomplexity/codeaudit)**.

+++


- **Addressing Weaknesses:**  
  Weaknesses found by SAST tools **MUST** be addressed by taking mitigation measures such as:  
  1. Rewriting the vulnerable code.  
  2. Adding a clear comment line explaining why the reported issue is not relevant.  
  3. Creating user documentation to notify users of potential risks.

+++

- **Least Privilege Principle:**  
  Programs **MUST** be designed and implemented according to the *principle of least privilege* for all functionality.

+++

- **Dangerous Built-ins:**  
  Avoid using Python built-in calls such as `compile()`, `eval()`, `exec()`, and `os.system()` to minimize security risks.

+++

- **Secrets Management:**  
  Hardcoded secrets **MUST NOT** be used.  
  If secrets are required (e.g., for API keys), they **MUST** be handled securely in code and stored using a secure secret management mechanism.

+++

- **Error Handling:**  
  Errors and exceptions **MUST** be handled securely.  
  Unhandled or verbose error messages can reveal sensitive information.

+++

- **File System Security:**  
  Secure functions from the `os` and `pathlib` modules **MUST** be used for handling file system paths.  
  Functions such as `os.path.realpath()` **SHOULD** be used to resolve symbolic links and **MAY** help prevent path traversal attacks.

+++

When using External Modules:
- All imported modules **MUST** be checked for known vulnerabilities. This **SHOULD** be done using [**Python Code Audit**](modulescan). **Python Code Audit** tool  uses the OSV (Open Source Vulnerability Database). Or by searching using the **[NVD](https://nocomplexity.com/documents/securityarchitecture/protection/vulnerabilities-search.html)**.


## Things to Avoid:

- A developer **SHOULD NOT** design or implement custom encryption protocols.  
  Designing encryption correctly requires specialized knowledge and skills.  
  Many security breaches have resulted from the use of custom encryption algorithms.

+++

- The Python `assert` statement **SHOULD NOT** be used in production code.  
  Assertions are intended for debugging and development only.  
  They can be disabled at runtime, and their use in production **MAY** introduce vulnerabilities. See also [this example](https://nocomplexity.com/stop-using-assert/).
  

+++

- The use of `subprocess.*` calls **SHOULD** be avoided whenever possible to prevent command injection vulnerabilities.

+++

- The use of dynamic imports (e.g., importing modules dynamically at runtime) **SHOULD** be avoided, as this can lead to the execution of untrusted code.

+++

- Extraction of untrusted or unknown archive files using `zipfile`, `lzma`, or `tarfile` **SHOULD** be avoided to prevent path traversal attacks.

+++

- Secrets **SHOULD NOT** be stored in Python code or files that will be uploaded in a code repository.

+++

 - `*pyc` files **SHOULD NOT** be checked in to source control. `pyc` files can contain secrets. Use a standard Python `.gitignore` file. Bad actors search for secrets in code, Python Bytecode (`.pyc` files ) and `.git` directories to find if a secret was ever uploaded in a source control system. 

 +++


:::{admonition} **Disclaimer**  
:class: note

These **Python Secure Coding Guidelines** are based on real-world breaches and [CWE](https://cwe.mitre.org/index.html) entries from the *Most Dangerous Software Weaknesses* list.  
 
However, a checklist is never a substitute for critical thinking. Cybersecurity is inherently complex, and mistakes are unavoidable.  
  
The [use of AI tools](https://nocomplexity.com/documents/simplifysecurity/useaisolutions.html#ai-ml-for-cyber-security) for coding **DOES NOT** guarantee that your Python code is secure by default.
:::


:::{hint} 
If you wish to provide feedback or suggest improvements to these guidelines, please open a [GitHub issue](https://github.com/nocomplexity/codeaudit). See also [section Help](help) if you want to contribute to this project!
:::
