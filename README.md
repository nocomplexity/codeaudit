# codeaudit

[![PyPI - Version](https://img.shields.io/pypi/v/codeaudit.svg)](https://pypi.org/project/codeaudit)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/codeaudit.svg)](https://pypi.org/project/codeaudit)

Codeaudit - A modern Python source code analyzer based on distrust.

Codeaudit is a tool designed to find security issues in Python code. This static application security testing (SAST) tool has great features to simplify the necessary security tasks and make it fun and easy. 

This tool is created for:
* Anyone who want or must check security risks with Python programs.
* Anyone who loves to create functionality using Python. So not only professional programs , but also occasional Python programmers or programmers who are used to working with other languages.
* Anyone who wants an easy way to get insight in possible security risks Python programs.


> [!WARNING]
> Codeaudit is still is currently in *beta status*. There are still bugs in the software that need to be fixed. Consider [contributing](CONTRIBUTING.md) to make Codeaudit a cool modern Python SAST tool. Codeaudit is currently in a thorough testing period and changes and fixes are frequently applied. 

## Features

Codeaudit has the following features:

* Detecting and reporting potential vulnerabilities of from all Python files collected in a directory. This is a must **do** check when researching python packages on possible security issues.

*  Detect and reports complexity and statistics relevant for security per Python file or from Python files found in a directory. 

* Codeaudit implements a light weight [cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) using Python’s Abstract Syntax Tree module. The codeaudit implemented check is by far good enough for determining security risks in Python files very quick!


*  Detect and reports which module are used within a Python file. Also vulnerability information found from used external modules is shown.

*  Detecting and reporting potential vulnerability issues within a Python file. Per detected issue the line number shown, with the lines that *could* cause a security issue.

* All output is saved in simple static HTML-reports. These reports can be examined in every browser. 


> [!IMPORTANT]
> Codeaudit uses the Python's Abstract Syntax Tree (AST) to get robust and reliable result. Using the Python AST makes contextual Vulnerability Detection possible and false positive are minimized.


## Installation

```console
pip install codeaudit
```

or use:

```bash
pip install -U codeaudit
```

If you have installed Codeaudit in the past and want to make sure you use the latest checks and features.

## Usage

After installation you can get an overview of all implemented commands. Just type in your terminal:

```text
codeaudit
```

This will show all commands:

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

## Example

By running the `codeaudit filescan` command, detailed security information is determined for a Python file based on more than **60 validations** implemented. 

The `codeaudit filescan` command shows all **potential** security issues that are detected in the source file in a HTML-report.

Per line a the in construct that can cause a security risks is shown, along with the relevant code lines where the issue is detected.

To scan a Python file on possible security issues, do:

```
codeaudit filescan ./codeaudit/tests/validationfiles/allshit.py 
Codeaudit report file created!
Check the report file: file:///home/jamesbrown/tmp/codeaudit-report.html
```

![Example view of filescan report](filescan.png)


## Contributing

All contributions are welcome! Think of corrections on the documentation, code or more and better tests.

Simple Guidelines:

* Questions, Feature Requests, Bug Reports please use on the Github Issue Tracker.

**Pull Requests are welcome!** 

When you contribute to Codeaudit, your contributions are made under the same license as the file you are working on. 


> [!NOTE]
> This is an open community driven project. Contributors will be mentioned in the documentation.

We adopt the [Collective Code Construction Contract(C4)](https://rfc.zeromq.org/spec/42/) to streamline collaboration.

## License


`codeaudit` is distributed under the terms of the [GPL-3.0-or-later](https://spdx.org/licenses/GPL-3.0-or-later.html) license.


