% THIS FILE IS GENERATED! - Use CLIcommands.ipynb to make it better!
# Commands Overview
Python Code Audit commands for: version: 1.4.2
```
----------------------------------------------------
 _                    __             _             
|_) \/_|_|_  _ __    /   _  _| _    |_|    _| o _|_
|   /  |_| |(_)| |   \__(_)(_|(/_   | ||_|(_| |  |_
----------------------------------------------------

Python Code Audit - A modern Python security source code analyzer based on distrust.

Commands to evaluate Python source code:
Usage: codeaudit COMMAND <directory|package>  [report.html] 

Depending on the command, you must specify a local directory, a Python file, or a package name hosted on PyPI.org.Reporting: The results are generated as a static HTML report for viewing in a web browser.

Commands:
  overview             Generates an overview report of code complexity and security indicators.
  filescan             Scans Python source code or PyPI packages for security weaknesses.
  modulescan           Generates a vulnerability report for imported Python modules.
  checks               Creates an HTML report of all implemented security checks.
  version              Prints the module version. Or use codeaudit [-v] [--v] [-version] or [--version].

Use the Python Code Audit documentation (https://codeaudit.nocomplexity.com) to audit and secure your Python programmes. Explore further essential open-source security tools at https://simplifysecurity.nocomplexity.com/

```
## codeaudit overview
```text
Generates an overview report of code complexity and security indicators.

This function analyzes a Python project to produce a high-level overview of
complexity and security-related metrics. The input may be either:

- A local directory containing Python source files
- The name of a package hosted on PyPI.org

For PyPI packages, the source distribution (sdist) is downloaded,
extracted to a temporary directory, scanned, and removed after the report
is generated.

The report includes summary statistics, security risk indicators based on
complexity and total lines of code, a list of discovered modules, per-file
metrics, and a visual overview. Results are written to a static HTML file.

Examples:
    Generate an overview report for a local project directory::

        codeaudit overview /projects/mycolleaguesproject

    Generate an overview report for a PyPI package::

        codeaudit overview linkaudit #A nice project on PyPI.org

        codeaudit overview pydantic  #A complex project on PyPI.org from a security perspective?

Args:
    directory (str): Path to a local directory containing Python source files
        or the name of a package available on PyPI.org.
    filename (str, optional): Name (and optional path) of the HTML file to
        write the overview report to. The filename should use the ``.html``
        extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

Returns:
    None. The function writes a static HTML overview report to disk.

Raises:
    SystemExit: If the provided path is not a directory, contains no Python
        files, or is neither a valid local directory nor a valid PyPI
        package name.    
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
Generates a vulnerability report for imported Python modules.

This function analyzes a single Python source file to identify imported
modules and checks externally imported modules against the OSV vulnerability
database. The results are compiled into a static HTML report.

For each detected external module, the report indicates whether known
vulnerability information exists and, if available, includes detailed
vulnerability data.

Progress information is printed to stdout while processing modules.

Example:
    Generate a module vulnerability report for a Python file::

        codeaudit modulescan mypythonfile.py 

Args:
    inputfile (str): Path to the Python source file to analyze.
    reportname (str, optional): Name (and optional path) of the HTML file
        to write the module vulnerability report to. The filename should
        use the ``.html`` extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

Returns:
    None. The function writes a static HTML report to disk.

Raises:
    None explicitly. File reading errors or invalid input are reported
    via standard output.

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
## codeaudit filescan
```text
Scans Python source code or PyPI packages for security weaknesses.

This function performs static application security testing (SAST) on a
given input, which can be:

- A local directory containing Python source code
- A single local Python file 
- A package name hosted on PyPI.org

Depending on the input type, the function analyzes the source code for
potential security issues, generates an HTML report summarizing the
findings, and writes the report to a static HTML file.

If a PyPI package name is provided, the function downloads the source
distribution (sdist), scans the extracted source code, and removes all
temporary files after the scan completes.

Example:
    Scan a local directory and write the report to ``report.html``::

        codeaudit filescan_/shitwork/custompythonmodule/ 

    Scan a single Python file::

        codeaudit filescan myexample.py

    Scan a package hosted on PyPI::

        codeaudit filescan linkaudit  #A nice project to check broken links in markdown files

        codeaudit filescan requests

Args:
    input_path (str): Path to a local Python file or directory, or the name
        of a package available on PyPI.org.
    filename (str, optional): Name (and optional path) of the HTML file to
        write the scan report to. The filename should use the ``.html``
        extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

Returns:
    None. The function writes a static HTML security report to disk.

Raises:
    None explicitly. Errors and invalid inputs are reported to stdout.    
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

Creates an HTML report of all implemented security checks.

This report provides a user-friendly overview of the static security checks 
currently supported by Python Code Audit. It is intended to make it easier to review 
the available validations without digging through the codebase.

The generated HTML includes:
- A table of all implemented checks
- The number of validations
- The version of Python Code Audit (codeaudit) used
- A disclaimer about version-specific reporting

The report is saved to the specified filename and is formatted to be 
embeddable in larger multi-report documents.

Help me continue developing Python Code Audit as free and open-source software.
Join the community to contribute to the most complete, local first , Python Security Static scanner.
Help!!  Join the journey, check: https://github.com/nocomplexity/codeaudit#contributing 


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
