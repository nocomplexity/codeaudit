# Get Started

## Installation

Codeaudit **SHOULD** be installed using `pip`:

```bash
pip install codeaudit
```

or use:

```bash
pip install -U codeaudit
```

If you have installed and used Python Codeaudit in the past and want to make benefit  of new checks and features.

:::{hint} 
It is recommended to use `pip` for installation. 

`Hatch` is used for packaging. By default [`Hatch`](https://hatch.pypa.io/latest/config/build/#reproducible-builds) supports [reproducible builds](https://nocomplexity.com/documents/securityarchitecture/prevention/reproduciblebuilds.html#reproducible-builds).
:::

:::{admonition} A default workflow
:class: tip

If you want to inspect a package or directory of Python files a simple workflow is:

1. Start with an overview: `codeaudit overview`

This will give valuable security statistics.

2. Do a file or directory scan: `codeaudit filescan` 

This will give a detailed report for all file(s) with potential security issues listed by line number.

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
