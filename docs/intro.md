# Introduction

![CodeauditLogo](images/codeauditlogo.png)

Codeaudit is a Python Static Application Security Testing (SAST) tool to find **potential security issues** in Python source files.

Codeaudit is designed to be:
* Simple to use.
* Simple to extend for various use cases.
* Powerful to determine *potential* security issues within Python code.

## Features
:::{admonition} This Python Code Audit tool has the following features:
:class: tip


* **Vulnerability Detection**: Identifies security vulnerabilities in Python files, essential for package security research.

+++

* **Complexity & Statistics**: Reports security-relevant complexity using a fast, lightweight [cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) count via Python's AST.

+++

* **Module Usage & External Vulnerabilities**: Detects used modules and reports vulnerabilities in external ones.


+++
* **Inline Issue Reporting**: Shows potential security issues with line numbers and code snippets.


+++
* **HTML Reports**: All output is saved in simple, static HTML reports viewable in any browser.


:::



## Background

There are not many good FOSS SAST tools for Python available. A good one is `Bandit`. However this `Bandit` has some constrains that makes the use not simple and lacks crucial but needed validations from a security perspective!


:::{note}
This `codeaudit` tool is designed to be fast and simple and easy to maintain library that can be extended for future needs.
:::


```{tableofcontents}
```
