# Features

Codeaudit is a modern Python source code analyzer based on distrust.

Codeaudit has the following features:
*  Detect and reports complexity and statistics per Python file or from a directory. Collected statistics are: 
    * Number_Of_Files
    * Number_Of_Lines
    * AST_Nodes
    * Number of used modules 
    * Functions
    * Classes
    * Comment_Lines

All statistics are gathered per Python file. A summary  is given for the inspected directory.

*  Detect and reports which module are used within a Python file.



*  Detecting and reporting potential vulnerability issues within a Python file.
Per detected issue the line number is given, along with the lines that *could* cause a security issue.



* Detecting and reporting potential vulnerabilities of from all Python files collected in a directory.
This is typically a must check when researching python packages on possible security issues.
