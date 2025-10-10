# Security Validations 

This section outlines the default security validations implemented in **Python Code Audit**.

**Python Code Audit** performs several types of analysis on Python programs, including:

* [**Static Application Security Testing (SAST)**](https://nocomplexity.com/python-security-what-is-sast/): Analyzes Python code statically to detect potential security vulnerabilities without executing it.

* **Cyclomatic Complexity Analysis**: Calculates complexity scores for each package and file to assess code maintainability and potential risk areas.

* **Vulnerability Reporting**: Identifies and reports known security vulnerabilities in the external modules used by the application.


## Static Application Security Validation Checks

A core feature of **Python Code Audit** is performing [Static Application Security Testing (SAST) on Python](https://nocomplexity.com/python-security-what-is-sast/) files and packages (directories).

The tool’s validation process targets common security weaknesses frequently found in Python programs, particularly those involving the use of **Python Standard Library (PSL)** calls.

**Python Code Audit** includes **the most comprehensive collection** of security rules for verifying the secure use of Python Standard Library functions. It analyzes your code for potential vulnerabilities based on these rules — all without executing the code.

All rules in Python Code Audit are based on:

* Common software flaws listed among the [CWE Top Dangerous Software Weaknesses](https://cwe.mitre.org/top25/index.html) relevant to Python

* Community input and contributions from security practitioners

* Real-world experience in mitigating vulnerabilities in Python applications

* Frequently reported security issues found in Python codebases

* Hidden code tricks that is on purpose obfuscated using advanced mechanisms. *Most Python SAST scanners will not find these vulnerabilities!*

* [Security-by-design principles](https://nocomplexity.com/documents/securitybydesign/intro.html), specifically tailored for Python development


Since Python Code Audit is [Free and Open Source Software (FOSS)](https://fsfe.org/), all validation rules are completely open and transparent — available for anyone to [use, review, and extend](https://github.com/nocomplexity/codeaudit).



If you notice a missing validation rule, we encourage you to [contribute!](CONTRIBUTE) See the [Contributing section](CONTRIBUTE) for details on how to get involved and help improve **Python Code Audit**.

:::{admonition} Join the [community](help)!
:class: tip
[Join the community](CONTRIBUTE) and be part of building the most comprehensive, local-first Python Security Audit Scanner.
Help us make Python code more secure — join the journey!

Or align [your brand with us](sponsors) — associate with an amazing open community around Python Code Audit, reinforcing your commitment to security innovation.
:::


:::{note} 
If the program uses modules from external modules that are **not** part of The Python Standard Library (PSL):
* Run Python Code Audit against this package and
* Run `codeaudit modulescan` to check if *known* vulnerabilities are reported for this module.

:::
 

:::

```{include} examples/checks.html
```