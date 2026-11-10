# Ctypes Statement

`ctypes` is a foreign function library for Python. It provides C compatible data types, and allows calling functions in DLLs or shared libraries. 

Python Code Audit checks on the use of:
- `ctypes.CDLL`
- `ctypes.WinDLL` 
- `ctypes.OleDLL` 
- `ctypes.windll.LoadLibrary` 
- `ctypes.cdll.LoadLibrary` 
- `ctypes.oledll.LoadLibrary`

:::{warning}
ctypes provides low-level access to native libraries and the process’s memory,**bypassing Python’s safety mechanisms and allowing execution of arbitrary native code.** Incorrect use can corrupt data and objects, reveal sensitive information, cause crashes, or otherwise compromise the running process.
:::

## Preventive measures

1. Never load libraries from untrusted or user-controlled input
2. Use `ctypes.util.find_library()` + explicit validation
3. Use absolute paths from a trusted location only
4. Apply the principle of least privilege / sandboxing
5. Validate and lock library integrity. From a secure supply chain perspective the loaded library must be checked using a good reproducible build approach.
6. Prefer safer alternatives when possible. So avoid using Python code that loads libraries that are hard to inspect upfront!


### More information

* [ctypes — A foreign function library for Python](https://docs.python.org/3/library/ctypes.html#module-ctypes)
* [Technical Malware Analysis Report: Python-based RAT Malware](https://www.cyfirma.com/research/technical-malware-analysis-report-python-based-rat-malware/)
* [Analysis of APT37 NarwhalRAT Leveraging MS-Themed Phishing and Dead-drop C2](https://www.genians.co.kr/en/blog/threat_intelligence/narwhalrat)
* [CVE-2026-102734](https://nvd.nist.gov/vuln/detail/cve-2026-102734)
* [CVE-2026-37008: CrewAI Python Sandbox Bypass RCE Vulnerability](https://www.sentinelone.com/vulnerability-database/cve-2026-37008/?utm_source=https%3A%2F%2Fwww.google.com%2F&utm_medium=organic-search)
