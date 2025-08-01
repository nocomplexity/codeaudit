# Features

Codeaudit is a modern Python source code analyzer based on distrust.


:::{admonition} This Python Code Audit tool has the following features:
:class: tip


* **Vulnerability Detection**: Identifies potential security issues in Python files. Crucial to check trust in Python modules and essential for security research.

+++

* **Complexity & Statistics**: Reports security-relevant complexity statistics using a fast, lightweight [cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) count by using Python AST.

+++

* **Module Usage & External Vulnerabilities**: Detects used modules and reports existing vulnerabilities in used modules.


+++
* **Inline Issue Reporting**: Shows potential security issues with line numbers and crucial code snippets. 


+++
* **HTML Reports**: All output is saved in simple, static HTML reports. Viewable in any browser.

:::

## More comprehensive outline:



Codeaudit has the has the following capabilities:

*  Detect and reports complexity and statistics per Python file or from a directory. 

Collected statistics are: 
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


