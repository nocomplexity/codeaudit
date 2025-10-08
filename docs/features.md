# Features

Python Code Audit is a modern Python source code analyzer based on distrust.


:::{admonition} Python Code Audit tool has the following features:
:class: tip


* **Vulnerability Detection**: Identifies potential security issues in Python files. Crucial to check trust in Python modules and essential for security research.

+++

* **Complexity & Statistics**: Reports security-relevant complexity statistics using a fast, lightweight [cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) count by using Python AST.

+++

* **Module Usage & External Vulnerabilities**: Detects used modules and reports known vulnerabilities in used modules.


+++
* **Inline Issue Reporting**: Shows potential security issues with line numbers and crucial code snippets. 


+++
* **HTML Reports**: All output is saved in simple, static HTML reports. Viewable in any browser.

:::

## In depth Capabilities outline

The Python Code Audit tool offers the following features to enhance code analysis and security:

- **Code Complexity and Statistics**: Analyzes individual Python files or entire directories to provide detailed metrics before execution. Collected statistics include:
  - Number of files
  - Total lines of code
  - AST nodes
  - Imported modules
  - Defined functions
  - Defined classes
  - Comment lines

  Per-file statistics are provided, along with a summary for the entire directory.

- **Module Usage Reporting**: Identifies and lists all modules used within each Python file.

- **Security Information on Modules**: Provides known security details for the modules used in your code.

- **Vulnerability Detection (Per File)**: Identifies potential security weaknesses within individual Python files, specifying the line number and code snippets that may pose risks.

- **Directory-Wide(for packages) Vulnerability Scanning**: Detects and reports security weaknesses across all Python files in a package(directory), essential for assessing the security of Python packages.


