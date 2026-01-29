# Command `codeaudit filescan`

The **Python Code Audit** `filescan` command efficiently scans Python files or directories (packages) to identify and report potential security weaknesses.

It produces a report detailing the potential security issues discovered.


See section [validations](checksinformation) for all security checks implemented!


To use the `codescan filescan` feature type in the console:

```
codeaudit filescan <pythonfile|package-name|directory>  [OUTPUTFILE]
```

**Python Code Audit** will create a detailed security scan report based on a single Python file, a local directory or a package on PyPI.org


So the input for `codeaudit filescan`  can be:
* A single Python file;
* A package on PyPI.org: Python Code Audit checks this package on security weakness, so cloning the sources local is not needed!
* A local directory with Python files, e.g. a local package development environment or a cloned package.

If you do not specify [OUTPUTFILE], a HTML output file, a HTML report file is created in the current directory and will be named codeaudit-report.html.

When running `codeaudit filescan` detailed information is determined for a Python file or package based on more than 70 validations implemented.

The `filescan` report lists all identified security weaknesses that could lead to a security vulnerability.

Per line a the in construct that can cause a security risks is shown, along with the relevant code lines where the issue is detected.

![Example view of filescan report](filescan.png)


:::{note} 
The `codeaudit filescan` command does **NOT** include all directories. This is done on purpose!

The following directories are skipped by default:
* `/docs`
* `/docker`
* `/dist`
* `/tests`
* all directories that start with `.` (dot) or `_` (underscore)
:::


## Example

```
codeaudit filescan ./codeaudit/tests/validationfiles/allshit.py 
Codeaudit report file created!
Check the report file: file:///home/maikel/tmp/codeaudit-report.html
```

Example report of a [codeaudit filescan report](examples/filescan.html) that is generated with the command `codeaudit filescan pythondev/codeaudit/tests/validationfiles/allshit.py`


## Help

```
NAME
    codeaudit filescan - Scans Python source code or PyPI packages for security weaknesses.

SYNOPSIS
    codeaudit filescan INPUT_PATH <flags>

DESCRIPTION
    This function performs static application security testing (SAST) on a
    given input, which can be:

    - A local directory containing Python source code
    - A single local Python file 
    - A package name hosted on PyPI.org

    codeaudit filescan <pythonfile|package-name|directory> [reportname.html]

    Depending on the input type, the function analyzes the source code for
    potential security issues, generates an HTML report summarizing the
    findings, and writes the report to a static HTML file.

    If a PyPI package name is provided, the function downloads the source
    distribution (sdist), scans the extracted source code, and removes all
    temporary files after the scan completes.

    Example:
        Scan a local directory and write the report to ``report.html``::

            codeaudit filescan_/shitwork/custompythonmodule/ 

        Scan a single Python file::

            codeaudit filescan myexample.py

        Scan a package hosted on PyPI::

            codeaudit filescan linkaudit  #A nice project to check broken links in markdown files

            codeaudit filescan requests

POSITIONAL ARGUMENTS
    INPUT_PATH
        Path to a local Python file or directory, or the name of a package available on PyPI.org.

FLAGS
    -f, --filename=FILENAME
        Default: 'codeaudit-report.html'
        Name (and optional path) of the HTML file to write the scan report to. The filename should use the ``.html`` extension. Defaults to ``DEFAULT_OUTPUT_FILE``.
NOTES
    You can also use flags syntax for POSITIONAL ARGUMENTS
```