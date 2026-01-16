# Features


**Python Code Audit** is a modern Python **security** source code analysis tool built on a *zero-trust* mindset. It focuses on identifying security risks, hidden behaviors, and trust boundaries in Python code—without executing it.

:::{admonition} Key Features of Python Code Audit
:class: tip

* **Vulnerability Detection**  
  Detects potential security issues in Python source files. This is essential for validating trust in third-party modules and supporting security research.

+++

* **External Egress Detection**  
  Identifies embedded API keys and logic that enables communication with remote services, helping uncover hidden data exfiltration paths.

+++

* **Complexity & Security-Relevant Statistics**  
  Reports code metrics relevant to security analysis, including a fast and lightweight
  [cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) calculation using the Python AST.

+++

* **Module Usage & Known Vulnerabilities**  
  Detects imported modules and correlates them with known security vulnerabilities.

+++

* **Inline Issue Reporting**  
  Highlights potential security issues directly in context, including line numbers and relevant code snippets.

+++

* **Static HTML Reports**  
  Generates clean, self-contained HTML reports that can be viewed in any modern web browser.

:::

## In-Depth Capability Overview

Python Code Audit provides a comprehensive set of features designed to enhance Python code security analysis:

### Code Complexity & Statistics

Analyzes individual Python files or entire packages *prior to execution* and collects security relevant metrics, including:

- Number of files
- Total lines of code
- AST node count
- Imported modules
- Defined functions
- Defined classes
- Comment lines

Statistics are reported per file, along with an aggregated summary for the entire package or directory.

### Module Usage Reporting

Identifies and lists all modules imported by each Python file, providing visibility into dependencies and potential attack surfaces.

### Module Security Intelligence

Surfaces known security information and vulnerabilities associated with the detected modules.

### Per-File Vulnerability Detection

Detects potential security weaknesses within individual Python files and reports:
- Affected line numbers
- Relevant code snippets
- Contextual details to aid investigation

### External Egress Detection

Scans for:
- Over 135 known API key formats
- Common networking and remote-connection patterns

This capability helps determine whether a Python file or library can transmit data to external services.

### Directory-Wide (Package-Level) Scanning

Performs vulnerability detection across all Python files in a directory or package, making it ideal for assessing the security posture of Python libraries and distributions.

### APIs for Integration

The Python Code Audit APIs empower you to build your own Python security tools or create seamless integrations you need! 
So create your own security dashboards, CICD integrations or custom integrations needed for your security management system. Powerfull but simple APIs are provided.
