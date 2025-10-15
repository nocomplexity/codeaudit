# Handling parsing errors

Only Python files that can be fully parsed are included in the **Python Code Security audit** scans.

Files are parsed using Python’s Abstract Syntax Tree (AST) module. If a file cannot be parsed due to invalid syntax or incompatibility with Python 3.x, an error will be reported (e.g., in the CLD). Such files cannot be analyzed and must be fixed to be included in the audit.

## Parsing Errors vs. Warnings
It is important to distinguish between parsing errors and warnings:
* **Parsing Errors**: Files that cause a parsing error are not analyzed. These errors indicate the code is fundamentally unreadable by the AST and **should be fixed**.
* **Warnings**: Python files may contain warnings, but these files are still fully parsed and analyzed. However, from a security standpoint, you should **also fix** Python files that produce warnings, as warnings often point to questionable or deprecated code practices.


See also the section of [Python warnings](warnings) to learn how **Python Code Audit** handles warnings.
