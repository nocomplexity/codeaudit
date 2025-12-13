# Command `codeaudit filescan`

The **Python Code Audit** `filescan` command efficiently scans Python files or directories (packages) to identify and report potential security weaknesses.

It produces a report detailing the potential security issues discovered.


See section [validations](checksinformation) for all security checks implemented!


To use the `codescan filescan` feature type in the console:

```
codeaudit filescan <INPUTFILE>  [OUTPUTFILE]
```

The `<INPUTFILE>` is mandatory. **Python Code Audit** will create a detailed security scan report. 


**`<INPUTFILE>`** can be:
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
    codeaudit filescan - Scans Python files or directories(packages) for vulnerabilities and reports potential issues.

SYNOPSIS
    codeaudit filescan INPUT_PATH <flags>

DESCRIPTION
    This function performs security validations on the specified file or directory, 
    formats the results into an HTML report, and writes the output to an HTML file. 

    You can specify the name of the outputfile and directory for the generated HTML report. Make sure you chose the extension `.html` since the output file is a static html file.

POSITIONAL ARGUMENTS
    INPUT_PATH

FLAGS
    -f, --filename=FILENAME
        Default: 'codeaudit-report.html'
        The name of the HTML file to save the report to. Defaults to `DEFAULT_OUTPUT_FILE`.

```
