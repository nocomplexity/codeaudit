# Introduction

[![PythonCodeAudit Badge](https://img.shields.io/badge/Python%20Code%20Audit-Security%20Verified-FF0000?style=flat-square)](https://github.com/nocomplexity/codeaudit)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10970/badge)](https://www.bestpractices.dev/projects/10970) 
[![PyPI - Version](https://img.shields.io/pypi/v/codeaudit.svg)](https://pypi.org/project/codeaudit)
[![Documentation](https://img.shields.io/badge/Python%20Code%20Audit%20Handbook-Available-blue)](https://nocomplexity.com/documents/codeaudit/intro.html)
[![License](https://img.shields.io/badge/License-GPLv3-FFD700)](https://nocomplexity.com/documents/codeaudit/license.html)

![CodeauditLogo](images/codeauditlogo.png)

Python Code Audit is a Static Application Security Testing (SAST) tool to find **security weaknesses** in Python source files.

:::{danger} 
A **security weakness** in Python code is an implementation flaw that could potentially become a **security vulnerability**.
:::


Python Code Audit offers a powerful yet straightforward security solution:

* **Ease of Use**: Simple to operate for quick audits.

* **Extensibility**: Easy to customize and adapt for diverse use cases.

* **Impactful Analysis**: Powerful detection of security weaknesses that have the potential to become critical vulnerabilities.



:::{warning} 
Python Code Audit gives you insight into potential security issues in your Python programs.

Are you ready to discover what's lurking in your code?

:::

## Features

:::{admonition} Python Code Audit has the following features:
:class: tip


* **Vulnerability Detection**: Identifies potential security issues in Python files. Crucial to check trust in Python modules and essential for security research.

+++

* **Complexity & Statistics**: Reports security-relevant complexity statistics using a fast, lightweight [cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) count by using Python (Abstract Syntax Tree) AST capabilities.

+++

* **Module Usage & External Vulnerabilities**: Detects used modules and reports known vulnerabilities in used modules.


+++
* **Inline Issue Reporting**: Shows potential security issues with line numbers and crucial code snippets. 


+++
* **HTML Reports**: All output is saved in simple, static HTML reports. Viewable in any browser.

:::



## Background

The availability of good, maintained FOSS SAST tools for Python is limited. While Bandit is a known tool, its usefulness is significantly limited: it struggles to identify a broad range of security weaknesses and fails to perform many crucial Python security validations. Additionally, its Command Line Interface (CLI) can present a steep learning curve for non-technical users. 

:::{hint} 
[To keep up with current threats, you need a Python Application Security Testing tool that evolves to deliver deeper insights and higher accuracy.](https://nocomplexity.com/stop-using-bandit/)
:::



:::{note}
This `Python Code Audit` tool is built to be fast, lightweight, and easy to use.

By default, the tool scans Python code against more than **70 rules** to detect potential security vulnerabilities. These rules target unsafe constructs of the standard Python libraries that could pose a security risk. 

:::

