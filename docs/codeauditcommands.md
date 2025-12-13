% THIS FILE IS GENERATED! - Use CLIcommands.ipynb to make it better!
# Commands Overview
Python Code Audit commands for: version: 1.3.0
```
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
  filescan             Scans Python code or packages on PyPI.org on security weaknesses.
  modulescan           Reports module vulnerability information.
  checks               Creates an HTML report of all implemented security checks.
  version              Prints the module version. Or use codeaudit [-v] [--v] [-version] or [--version].

Use the Codeaudit documentation to check the security of Python programs and make your Python programs more secure!
Check https://simplifysecurity.nocomplexity.com/ 

```
## Code Audit overview
```text
Reports complexity and statistics for Python files in a project directory.

Parameters:
    directory (str): Path to the directory to scan.
    filename (str): Output filename for the HTML report.
str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to 'utf-8'.
errors defaults to 'strict'.
```
## Code Audit modulescan
```text
Reports module vulnerability information.str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to 'utf-8'.
errors defaults to 'strict'.
```
## Code Audit filescan
```text
Scans Python code or packages on PyPI.org on security weaknesses.
    
This function performs security validations on the specified file or directory, 
formats the results into an HTML report, and writes the output to an HTML file. 

You can specify the name of the outputfile and directory for the generated HTML report. Make sure you chose the extension `.html` since the output file is a static html file.

Parameters:
    file_to_scan (str)      : The full path to the Python source file to be scanned.
    filename (str, optional): The name of the HTML file to save the report to.
                              Defaults to `DEFAULT_OUTPUT_FILE`.

Returns:
    None - A HTML report is written as output
str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to 'utf-8'.
errors defaults to 'strict'.
```
## Code Audit checks
```text

Creates an HTML report of all implemented security checks.

This report provides a user-friendly overview of the static security checks 
currently supported by codeaudit. It is intended to make it easier to review 
the available validations without digging through the codebase.

The generated HTML includes:
- A table of all implemented checks
- The number of validations
- The version of codeaudit used
- A disclaimer about version-specific reporting

The report is saved to the specified filename and is formatted to be 
embeddable in larger multi-report documents.

Parameters:
    filename (str): The output HTML filename. Defaults to 'codeaudit_checks.html'.
str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to 'utf-8'.
errors defaults to 'strict'.
```
## Code Audit version
```text
Prints the module version. Or use codeaudit [-v] [--v] [-version] or [--version].str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to 'utf-8'.
errors defaults to 'strict'.
```
