# Command `codeaudit modulescan`

The Codeaudit `modulescan` command creates a report with valuable security information on used modules.

The modulescan module works per file.

To use modulescan feature do:

```text
codeaudit modulescan <INPUTFILE>  [OUTPUTFILE]
```

The `<INPUTFILE>` is mandatory. Codeaudit will create a modulescan report for the given Python file.

If you do not specify [OUTPUTFILE], a HTML output file, a HTML report file is created in the current directory and will be named `codeaudit-report.html`.

When running `codeaudit modulescan` detailed information is determined for a Python file of:
* Core modules used and
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

You will see the followng help in the terminal:

```text
NAME
    codeaudit modulescan - Reports module information per file.

SYNOPSIS
    codeaudit modulescan INPUTFILE <flags>

DESCRIPTION
    Reports module information per file.

POSITIONAL ARGUMENTS
    INPUTFILE

FLAGS
    -r, --reportname=REPORTNAME
        Default: 'codeaudit-report.html'
```