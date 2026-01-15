# Security Validation

You can scan any Python file, local directory, or PyPI package using Python Code Audit.

## Usage
1. Overview:
```
codeaudit overview <directory|package> [report.html]
```
 Generates an overview report detailing code complexity and security indicators.

2. SAST scan: 
```
codeaudit filescan <file|directory|package> [report.html]
```
Scans Python source code or PyPI packages for security weaknesses.

3. Check for known vulnerabilities in imported libraries:
```
codeaudit modulescan <file|package> [report.html]
```
Generates a report on known vulnerabilities within Python modules and packages.

You can choose a custom name for the generated HTML report. These reports are static files that can be viewed immediately in any web browser.


:::{admonition} A default workflow
:class: tip

If you want to inspect a package or directory of Python files a simple workflow is:

1. Start with an overview: `codeaudit overview`

This will give valuable security statistics.

2. Run a security scan (SAST scan): `codeaudit filescan` 

This will give a detailed report for all file(s) with **potential security issues** listed by line number. 
Including if a file has an external Egress Risk. There will also be a check on Possible API keys or logic for connecting to remote services in the code.

3. Inspect the used modules of a file on reported vulnerabilities by: `codeaudit modulescan`

This will give a detailed report on known vulnerabilities for a module.

:::


## CodeAudit commands

Codeaudit has a few powerful CLI commands to satisfy your curiosity about security issues in Python files.

```{tableofcontents}
```



## Getting help

After installation you can get an overview of all implemented commands. Type in your terminal:

```bash
codeaudit
```

This will show:

```text
----------------------------------------------------
 _                    __             _             
|_) \/_|_|_  _ __    /   _  _| _    |_|    _| o _|_
|   /  |_| |(_)| |   \__(_)(_|(/_   | ||_|(_| |  |_
----------------------------------------------------

Python Code Audit - A modern Python security source code analyzer based on distrust.

Commands to evaluate Python source code:
Usage: codeaudit COMMAND [PATH or FILE]  [OUTPUTFILE] 

Depending on the command, a directory or file name must be specified. The output is a static HTML file to be examined in a browser. Specifying a name for the output file is optional.

Commands:
  overview             Reports complexity and statistics for Python files in a project directory.
  filescan             Scans Python projects/files, reporting potential security weaknesses.
  modulescan           Reports module vulnerability information.
  checks               Creates an HTML report of all implemented security checks.
  version              Prints the module version. Or use codeaudit [-v] [--v] [-version] or [--version].

Use the Codeaudit documentation to check the security of Python programs and make your Python programs more secure!
Check https://simplifysecurity.nocomplexity.com/ 
```
