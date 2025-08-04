% THIS FILE IS GENERATED! - Use CLIcommands.ipynb to make it better!
# Overview of Codeaudit commands
Codeaudit commands for: version: 0.8.0
```
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
  directoryscan        Reports potential security issues for all Python files found in a directory.
  filescan             Reports potential security issues for a single Python file.
  modulescan           Reports module information per file.
  checks               Generate an HTML report of all implemented codeaudit security checks.
  version              Prints the module version. Use [-v] [--v] [-version] or [--version].

Use the Codeaudit documentation to check the security of Python programs and make your Python programs more secure!
Check https://simplifysecurity.nocomplexity.com/ 

```
## codeaudit overview
```text
Reports Complexity and statistics per Python file from a directory.

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
## codeaudit modulescan
```text
Reports module information per file.str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to 'utf-8'.
errors defaults to 'strict'.
```
## codeaudit filescan
```text
Reports potential security issues for a single Python file.

This function performs security validations on the specified file, 
formats the results into an HTML report, and writes the output to an HTML file. 

You can specify the name and directory for the generated HTML report.

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
## codeaudit directoryscan
```text
Reports potential security issues for all Python files found in a directory.

This function performs security validations on all files found in a specified directory.
The result is written to a HTML report. 

You can specify the name and directory for the generated HTML report.

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
## codeaudit checks
```text

Generate an HTML report of all implemented codeaudit security checks.

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
## codeaudit version
```text
Prints the module version. Use [-v] [--v] [-version] or [--version].str(object='') -> str
str(bytes_or_buffer[, encoding[, errors]]) -> str

Create a new string object from the given object. If encoding or
errors is specified, then the object must expose a data buffer
that will be decoded using the given encoding and error handler.
Otherwise, returns the result of object.__str__() (if defined)
or repr(object).
encoding defaults to 'utf-8'.
errors defaults to 'strict'.
```
