% THIS FILE IS GENERATED! - Use CLIcommands.ipynb to make it better!
# Commands Overview
Python Code Audit commands for: version: 1.9.2
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
  overview             Generate an overview report of code complexity and security indicators.
  filescan             Scan Python source code, PyPI packages, or tar.gz archives for security weaknesses.
  cimode               Run a SAST scan for CI workflows.
  modulescan           Generate a report on known vulnerabilities in Python modules and packages.
  checks               Creates an HTML report of all implemented security checks.
  version              Prints the module version. Or use codeaudit [-v] [--v] [-version] or [--version].

Use the Python Code Audit documentation (https://codeaudit.nocomplexity.com) to audit and secure your Python programmes. Explore further essential open-source security tools at https://pythonsecurity.nocomplexity.com/

```
## codeaudit overview
```text
Generate an overview report of code complexity and security indicators.

This function analyzes a Python project and generates a high-level HTML
overview of code complexity, project size, module dependencies, and
security-related indicators.

The input can be one of the following:

* A local directory containing Python source files
* A local or remote ``.tar.gz`` source archive
* The name of a package hosted on PyPI.org

codeaudit overview <package-name|directory|archive.tar.gz> [reportname.html]

For a local or remote ``.tar.gz`` archive, the archive is validated,
extracted to a temporary directory, scanned, and removed after the report
has been generated.

For a PyPI package, the source distribution (sdist) is downloaded,
extracted to a temporary directory, scanned, and removed after the report
has been generated.

The report includes:

* Summary statistics for the analyzed project
* Security concern indicators based on maximum code complexity
  and total lines of code
* A list of discovered standard-library and external modules
* Detailed metrics for each Python source file
* A visual overview of the collected metrics
* Advice for performing a full SAST scan with ``codeaudit filescan``

Examples:
    Generate an overview report for a local project directory::

        codeaudit overview /projects/mycolleaguesproject

    Generate an overview report for a local ``.tar.gz`` archive::

        codeaudit overview /path/to/myproject.tar.gz

    Generate an overview report for a remote ``.tar.gz`` archive::

        codeaudit overview https://example.com/myproject.tar.gz

    Generate an overview report for a PyPI package::

        codeaudit overview linkaudit

        codeaudit overview pydantic

    Specify an output report file::

        codeaudit overview /projects/mycolleaguesproject report.html

Args:
    directory (str): Path to a local directory containing Python source
        files, a local or remote ``.tar.gz`` source archive, or the name of
        a package available on PyPI.org.
    filename (str, optional): Name (and optional path) of the HTML file to
        write the overview report to. The filename should use the
        ``.html`` extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

Returns:
    None: The function writes a static HTML overview report to disk.

Raises:
    SystemExit: If the provided path is not a directory, contains no
        Python files, is an invalid ``.tar.gz`` archive, or is neither a
        valid local input nor a valid PyPI package name.
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

Generate a report on known vulnerabilities in Python modules and packages.

This function analyzes a single Python file to identify imported
external modules and checks those modules against the OSV vulnerability
database. The collected results are written to a static HTML report.

If the input refers to a valid PyPI package name instead of a local Python
file, the function generates a vulnerability report directly for that
package.

While processing modules, progress information is printed to standard
output.

Example:
    Generate a module vulnerability report for a Python file::

        codeaudit modulescan <pythonfile>|<package> [yourreportname.html]

        codeaudit modulescan mypythonfile.py

Args:
    inputfile (str): Path to a Python source file (*.py) to analyze, or the
        name of a package available on PyPI.
    reportname (str, optional): Name (and optional path) of the HTML file to
        write the vulnerability report to. The filename should use the
        ``.html`` extension. Defaults to ``DEFAULT_OUTPUT_FILE``.

Returns:
    None: The function writes a static HTML report to disk.

Raises:
    SystemExit: If the input is not a valid Python file or a valid PyPI
        package. File parsing and I/O errors are reported via standard
        output before exiting.
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
Scan Python source code, PyPI packages, or tar.gz archives for security weaknesses.

This function performs static application security testing (SAST) on a
specified input. The input can be one of the following:

* A local directory containing Python source code
* A single local Python file
* A local or remote ``.tar.gz`` source archive
* The name of a package hosted on PyPI

codeaudit filescan <pythonfile|package-name|directory|archive.tar.gz> [reportname.html] [--nosec]

Based on the input type, the function analyzes the source code for potential
security issues, generates an HTML report summarizing the findings, and
writes the report to disk.

For a local or remote ``.tar.gz`` archive, the archive is validated,
extracted to a temporary directory, scanned as a source directory, and
cleaned up after the scan completes.

If a PyPI package name is provided, the function downloads the source
distribution (sdist), extracts it to a temporary directory, scans the
extracted source code, and cleans up all temporary files after the scan
completes.

Examples:

    Scan a local directory and write the report to ``report.html``::

        codeaudit filescan /path/to/custompythonmodule report.html

    Scan a local directory::

        codeaudit filescan /path/to/project

    Scan a single Python file::

        codeaudit filescan myexample.py

    Scan a local tar.gz archive::

        codeaudit filescan /path/to/package.tar.gz

    Scan a remote tar.gz archive::

        codeaudit filescan https://example.com/package.tar.gz

    Scan a package hosted on PyPI::

        codeaudit filescan linkaudit

        codeaudit filescan requests

    Specify an output report file::

        codeaudit filescan /path/to/project report.html

    Enable filtering of issues marked with ``#nosec`` or another marker
    indicating that potential code weaknesses have been reviewed or
    intentionally ignored::

        codeaudit filescan myexample.py --nosec

POSITIONAL ARGUMENTS
INPUT_PATH
    Path to a local Python file or directory, a local or remote ``.tar.gz``
    archive, or the name of a package available on PyPI.

FLAGS
-f, --filename=FILENAME
    Default: 'codeaudit-report.html'
    Name (and optional path) of the HTML file to write the scan report to.
    The filename should use the ``.html`` extension.

-n, --nosec=NOSEC
    Default: False
    Whether to filter out issues marked as reviewed or ignored in the
    source code.

Args:
    input_path (str): Path to a local Python file or directory, a local or
        remote ``.tar.gz`` archive, or the name of a package available on
        PyPI.
    filename (str, optional): Name (and optional path) of the HTML file to
        write the scan report to. The filename should use the ``.html``
        extension. Defaults to ``DEFAULT_OUTPUT_FILE``.
    nosec (bool, optional): Whether to filter out issues marked as reviewed
        or ignored in the source code. Defaults to ``False``, meaning no
        filtering is applied.

Returns:
    None: The function writes a static HTML security report to disk.

Raises:
    None: Errors and invalid inputs are reported to stdout.
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
