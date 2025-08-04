# Getting Started

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
2. Do a directory scan: `codeaudit directoryscan` OR
3. OR Scan files of interest with: `codeaudit filescan` 
4. Inspect the used modules of a file on reported vulnerabilties by: `codeaudit modulescan`

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
--------------------------------------------------
   _____          _                      _ _ _   
  / ____|        | |                    | (_) |  
 | |     ___   __| | ___  __ _ _   _  __| |_| |_ 
 | |    / _ \ / _` |/ _ \/ _` | | | |/ _` | | __|
 | |___| (_) | (_| |  __/ (_| | |_| | (_| | | |_ 
  \_____\___/ \__,_|\___|\__,_|\__,_|\__,_|_|\__|
--------------------------------------------------

Codeaudit - Modern Python source code analyzer based on distrust.

Commands to evaluate Python source code:
Usage: codeaudit COMMAND [PATH or FILE]  [OUTPUTFILE] 

Depending on the command, a directory or file name must be specified. The output is a static HTML file to be examined in a browser. Specifying a name for the output file is optional.

Commands:
  overview             Reports Complexity and statistics per Python file from a directory.
  modulescan           Reports module information per file.
  filescan             Reports potential security issues for a single Python file.
  directoryscan        Reports potential security issues for all Python files found in a directory.
  checks               Generate an HTML report of all implemented codeaudit security checks.
  version              Prints the module version. Use [-v] [--v] [-version] or [--version].

Use the Codeaudit documentation to check the security of Python programs and make your Python programs more secure!
Check https://simplifysecurity.nocomplexity.com/ 
```
