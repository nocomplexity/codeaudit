
# Codeaudit Overview

`Codeaudit overview` is created to give a quick insight in possible security issues.

For every Python file the following security relevant statistics are determined:
* Number Of Code Lines: Too much means more energy to keep the security risks manageable. Files with a large number of LoCs (Lines Of Code) means besides extra effort for maintenance and activities needed to keep security risks zero.
* Number of AST_Nodes: Codeaudit calculates Abstract Syntax Trees (ASTs) to give a solid insight in the complexity of Python source code.
* Number of Modules: A high the number of used modules can mean more security risks. To get more insight in modules used in a Python file you **SHOULD** use the `codeaudit modulescan` command!
* Number of Functions.
* Number of Classes 
* Number of Comment_Lines
* Complexity_Score: Per file the complexity of file is determined. A high score means more possible security risks.
* Number of Warnings: A normal Python source file should not give Warnings. Warnings should be solved to prevent security risks in future.



To get a quick overview and core statistics that give a **solid** insight in the security of Python files of a directory do:

```text
codeaudit overview <DIRECTORY> [OUTPUTFILE]
```

The `DIRECTORY` is mandatory. Codeaudit will search for **all** Python files in this directory. It can even be e.g.:
* `.` for scanning and using the current directory for an overview report.
* `\src` for scanning and reporting on Python files found in the `\src` directory.

If you do not specify a HTML output file, a HTML report file is created in the current directory and will be named `codeaudit-report.html`.


## Example

Example of an [overview report](examples/overview.html) that is generated with the command:

```
codeaudit overview /src/linkaudit
```

An overview plot  is generated to quickly get insight in possible problematic files. E.g. files that have a high complexity count or files that a large number of Lines Of Code (LoCs). Large files and files with a high complexity rating should be distrusted by default from a security perspective. 

Example of an overview plot:
![overview visual](overviewplot.png)

## Syntax

```text
NAME
    codeaudit overview - Reports Complexity and statistics per Python file from a directory.

SYNOPSIS
    codeaudit overview DIRECTORY <flags>

DESCRIPTION
    Reports Complexity and statistics per Python file from a directory.

POSITIONAL ARGUMENTS
    DIRECTORY
        Path to the directory to scan.

FLAGS
    -f, --filename=FILENAME
        Default: 'codeaudit-report.html'
        Output filename for the HTML report.

```
