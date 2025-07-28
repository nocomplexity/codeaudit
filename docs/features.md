# Features

Codeaudit is a modern Python source code analyzer based on distrust.

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


More in detph outlined:

Codeaudit has the following features:
*  Detect and reports complexity and statistics per Python file or from a directory. Collected statistics are: 
    * Number_Of_Files
    * Number_Of_Lines
    * AST_Nodes
    * Number of used modules 
    * Functions
    * Classes
    * Comment_Lines

* All statistics are gathered per Python file. A summary is given for the inspected directory.

*  Detect and reports which module are used within a Python file.

*  Reports valuable known security information on used modules.

*  Detecting and reporting **potential vulnerability issues** within a Python file.
Per detected issue the line number is given, along with the lines that *could* cause a security issue.


* Detecting and reporting potential vulnerabilities from all Python files collected in a directory.
This is typically a must check when researching python packages on possible security issues.
