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

* Detecting and reporting potential vulnerabilities of from all Python files collected in a directory. This is a must **do** check when researching python packages on possible security issues.

*  Detect and reports complexity and statistics relevant for security per Python file or from Python files found in a directory. 

* Codeaudit implements a light weight [cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) using Python’s Abstract Syntax Tree module. The codeaudit implemented check is by far good enough for determining security risks in Python files very quick!


*  Detect and reports which module are used within a Python file. Also vulnerability information found from used external modules is shown.

*  Detecting and reporting potential vulnerability issues within a Python file. Per detected issue the line number shown, with the lines that *could* cause a security issue.

* All output is saved in simple static HTML-reports. These reports can be examined in every browser. 
:::



## Background

There are not many FOSS SAST tools for Python available that are simple. The most used and certainly a good one is `Bandit`. However this `Bandit` has some constrains that makes the use not simple and lacks crucial but needed validations.


:::{note}
This `codeaudit` tool is designed to be fast and simple and easy to maintain library that can be extended for future needs.
:::


```{tableofcontents}
```
