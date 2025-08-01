# Command `codeaudit filescan`

The Codeaudit filescan command creates a report with valuable security information for potential security issues in the Python file.
See section [validations](checksinformation) for all security checks implemented!

The filescan module works per file.

To use the `codescan filescan` feature type in the console:

```
codeaudit filescan <INPUTFILE>  [OUTPUTFILE]
```

The `<INPUTFILE>` is mandatory. Codeaudit will create a detailed security scan report for the given Python file.

If you do not specify [OUTPUTFILE], a HTML output file, a HTML report file is created in the current directory and will be named codeaudit-report.html.

When running codeaudit filescan detailed information is determined for a Python file based on more than 60 validations implemented.

The filescan report shows all **potential** security issues that are detected in the source file.
Per line a the in construct that can cause a security risks is shown, along with the relevant code lines where the issue is detected.

![Example view of filescan report](filescan.png)

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
    codeaudit filescan - Reports potential security issues for a single Python file.

SYNOPSIS
    codeaudit filescan FILE_TO_SCAN <flags>

DESCRIPTION
    This function performs security validations on the specified file, 
    formats the results into an HTML report, and writes the output to an HTML file. 

    You can specify the name and directory for the generated HTML report.

POSITIONAL ARGUMENTS
    FILE_TO_SCAN
        The full path to the Python source file to be scanned.

FLAGS
    -f, --filename=FILENAME
        Default: 'codeaudit-report.html'
        The name of the HTML file to save the report to. Defaults to `DEFAULT_OUTPUT_FILE`.
```
