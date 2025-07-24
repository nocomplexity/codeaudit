# Getting Started

## Installation

Codeaudit can be installed using `pip`:

```bash
pip install codeaudit
```

or use:

```bash
pip install -U codeaudit
```

If you have installed Codeaudit in the past and want to make sure you use the latest checks and features.


## CodeAudit commands

Codeaudit has a few powerful CLI commands to satisfy your curiosity about security issues in Python files.

```{tableofcontents}
```




## Getting help

After installation you can get an overview of all implemented commands. Just type in your terminal:

```text
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
