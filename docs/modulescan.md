# Command `codeaudit modulescan`

The Codeaudit `modulescan` command creates a report with valuable security information on used modules.

The modulescan module works per file or package present on PyPI.org

To use modulescan feature do:

Generate a module vulnerability report for a Python file::

* `codeaudit modulescan <pythonfile>|<package> [yourreportname.html]`
* `codeaudit modulescan mypythonfile.py`



If you do not specify a reportname , a HTML output file, a HTML report file is created in the current directory and will be named `codeaudit-report.html`.

When running `codeaudit modulescan` detailed information is determined for a Python file of:
* Core modules used (aka "built-in modules" or "standard modules") and
* Imported modules used (aka external modules that are not part of the Python Standard Library)
* Vulnerability information (**if available**) for all imported modules. The OSV (Open Source Vulnerability Data is used) for retrieving vulnerability information. OSV is a Google FOSS project to improve the security of FOSS projects. See the [Open Security Architecture](https://nocomplexity.com/documents/securityarchitecture/references/vulnerabilitydatabases.html#vulnerability-databases) for more information.



## Example

```
codeaudit modulescan ../codeaudit/tests/validationfiles/modulecheck.py 
Progress: |██████████████████████████████████████████████████| 100.0% Complete
Codeaudit report file created!
Check the report file: file:///home/maikel/tmp/codeaudit-report.html
```


Example of an [codeaudit modulescan report](examples/modulescan.html) that is generated with the command `codeaudit modulescan pythondev/codeaudit/tests/validationfiles/modulecheck.py`



## module overview --help

When using:

```
codeaudit modulescan --help
```

You will see the following help in the terminal:

```text
NAME
    codeaudit modulescan - Generate a report on known vulnerabilities in Python modules and packages.

SYNOPSIS
    codeaudit modulescan INPUTFILE <flags>

DESCRIPTION
    This function analyzes a single Python file to identify imported
    external modules and checks those modules against the OSV vulnerability
    database. The collected results are written to a static HTML report.

    If the input refers to a valid PyPI package name instead of a local Python
    file, the function generates a vulnerability report directly for that
    package.

    While processing modules, progress information is printed to standard
    output.

    Example:
        Generate a module vulnerability report for a Python file::

            codeaudit modulescan <pythonfile>|<package> [yourreportname.html]

            codeaudit modulescan mypythonfile.py

POSITIONAL ARGUMENTS
    INPUTFILE
        Path to a Python source file (*.py) to analyze, or the name of a package available on PyPI.

FLAGS
    -r, --reportname=REPORTNAME
        Default: 'codeaudit-report.html'
        Name (and optional path) of the HTML file to write the vulnerability report to. The filename should use the ``.html`` extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS

```