
# Command `codeaudit overview`



Use this command to generate a quick security relevant assessment of a Python project or package. It provides an overview of important security metrics for the project.

Usage
```Bash
codeaudit overview <package-path|package-name> [report-name.html]
```

Arguments:
* `<package-path|package-name>` (Required)
Specify either a local directory containing Python files or the name of a Python package hosted on PyPI.org.

* `[report-name.html]` (Optional)
The filename for the generated security report. If omitted, the tool will use a default filename. If you provide a custom name, ensure it ends with the `.html` extension.



For every Python file the following **security** relevant statistics are determined:

* **Number Of Code Lines**: Too many Lines Of Code (LoC) means a higher risk. Large code bases require a lot of effort to keep the security risks manageable. A large number of LoCs (Lines Of Code) means extra effort for maintenance there is a severe risks that new features or fixes will introduce new security risks.

* **Number of AST_Nodes**: Codeaudit calculates the number or 'AST Nodes' based on creating an Abstract Syntax Tree (AST) of a file. This to give a solid insight in the complexity of Python source code. Code Audit does not simply counts nodes, but complexity is determined by an algorithm where e.g. the number of `if-else` loops is counted and weighted. More information about complexity can be found in the section [Codeaudit complexity Check](complexitycheck).

* **Number of Modules**: A high the number of used modules used within a Python file can mean more security risks. This since there are more dependencies to manage. To get more insight in modules used in a Python file you **SHOULD** use the `codeaudit modulescan` command!

* **Number of Functions**. There is no such thing as a perfect architecture for Python programs. However there are many programs that are simple **bad** designed. Too many functions in one Python file in combination with one of the other statistics is an indication for possible security risks.

* **Number of Classes**. 

* **Number of Comment_Lines**. Python files with too little or too many comment lines can have impact on maintenance from a security point of view. 

* **Complexity_Score**: Per file the complexity of file is determined. A high complexity score can in potential result in more possible security risks. More information about complexity can be found in the section [Codeaudit complexity Check](complexitycheck).

* **Number of Warnings**: A normal Python source file should not give Warnings. Warnings should be solved to prevent security risks in future. 



To get a quick overview and core statistics that gives a **solid** insight in possible security risks of Python files of a Python program (module) or directory of Python files do:

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
    codeaudit overview - Generates an overview report of code complexity and security indicators.

SYNOPSIS
    codeaudit overview DIRECTORY <flags>

DESCRIPTION
    This function analyzes a Python project to produce a high-level overview of
    complexity and security-related metrics. The input may be either:

    - A local directory containing Python source files
    - The name of a package hosted on PyPI.org

    So:
    codeaudit overview <package-name|directory> [reportname.html]

    For PyPI packages, the source distribution (sdist) is downloaded,
    extracted to a temporary directory, scanned, and removed after the report
    is generated.

    The report includes summary statistics, security risk indicators based on
    complexity and total lines of code, a list of discovered modules, per-file
    metrics, and a visual overview. Results are written to a static HTML file.

    Examples:
        Generate an overview report for a local project directory::

            codeaudit overview /projects/mycolleaguesproject

        Generate an overview report for a PyPI package::

            codeaudit overview linkaudit #A nice project on PyPI.org

            codeaudit overview pydantic  #A complex project on PyPI.org from a security perspective?

POSITIONAL ARGUMENTS
    DIRECTORY
        Path to a local directory containing Python source files or the name of a package available on PyPI.org.

FLAGS
    -f, --filename=FILENAME
        Default: 'codeaudit-report.html'
        Name (and optional path) of the HTML file to write the overview report to. The filename should use the ``.html`` extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```
