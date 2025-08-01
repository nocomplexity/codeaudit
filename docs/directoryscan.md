# Command `codeaudit directoryscan`

The Codeaudit directoryscan command creates a report with valuable security information for potential security issues from all Python file present in a directory.

See section [validations](checksinformation) for all security validations that are are used when scanning code. 



To use the `codeaudit directoryscan` feature do:

```
codeaudit directoryscan <DIRECTORY>  [OUTPUTFILE]
```

`<DIRECTORY>` is mandatory. Codeaudit will create a detailed security scan report for the given directory. 


If you do not specify [OUTPUTFILE], a HTML output file, a HTML report file is created in the current directory and will be named codeaudit-report.html.

When running codeaudit directoryscan detailed security information is determined for all found Python files in the directory. The scan is based on more than 60 validations implemented.

:::{note} 
Files that cannot parsed into the Python AST will be skipped. An error is printed in the console.
This can occur with Python 2 files or files that are never meant to be compiled. E.g. code-snippets or parts of example files with a `*.py` extension.

:::


The `codeaudit directoryscan` report shows all **potential** security issues that are detected in the source file.
Per line a the in construct that can cause a security risks is shown, along with the relevant code lines where the issue is detected.

The `codeaudit directoryscan` feature works on a directory. Within this directory all relevant Python files are discovered and validated against a large number of potential security issues.

:::{note} 
The `codeaudit directoryscan` does **NOT** include all directories. This is done on purpose!

The following directories are skipped by default:
* `/docs`
* `/docker`
* `/dist`
* `/tests`
* all directories that start with `.` (dot) or `_` (underscore)

:::

## Example


Example report of a [codeaudit directory report](examples/directoryscan.html) that is generated with the command `codeaudit directoryscan pythondev/codeaudit/tests/validationfiles/`



## Help

```
NAME
    codeaudit directoryscan - Reports potential security issues for all Python files found in a directory.

SYNOPSIS
    codeaudit directoryscan DIRECTORY_TO_SCAN <flags>

DESCRIPTION
    This function performs security validations on all files found in a specified directory.
    The result is written to a HTML report. 

    You can specify the name and directory for the generated HTML report.

POSITIONAL ARGUMENTS
    DIRECTORY_TO_SCAN

FLAGS
    -f, --filename=FILENAME
        Default: 'codeaudit-report.html'
        The name of the HTML file to save the report to. Defaults to `DEFAULT_OUTPUT_FILE`.
```