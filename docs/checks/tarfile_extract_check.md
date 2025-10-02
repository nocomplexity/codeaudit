# TarFile Statement

The Python `tarfile` module makes it possible to read and write tar archives.

Code Audit checks on the use of:
* `TarFile.extract` and
* `TarFile.extractall`
Using these methods in Python code can give serious security concerns.


:::{admonition} The default rule is:
:class: danger
Assume all input is malicious.
:::

Using these commands in Python code can expose systems to several risks:

* Privilege escalation: An attacker can change file permissions on sensitive files (for example, `/etc/shadow` or SSH keys) if the extraction process runs with root or elevated privileges.

* Sandbox escape: Many systems rely on extraction directories or temporary paths for isolation; malicious archives can break that isolation and allow code to operate outside the sandbox.

* Tampering and log evasion: By modifying file timestamps or other metadata, an attacker can obscure activity, confuse forensic timelines, or mislead incident response.

* Easy exploitation: Crafting a malicious tarball is straightforward and requires no specialized tools, making exploitation trivial for an attacker.


:::{danger} 
Using `TarFile.extractall` or `TarFile.extract` is dangerous.
Always. So good mitigation measurement **must** be present in the code!
:::

But besides using these `tarfile` commands in your Python code, there have been some vulnerabilities with the `tarfile` module implementation in CPython in the past. 

So from a security point of view checking if your code is extracting files using the `tarfile` command is vital. 

:::{note} 
Use of the `tarfile` extraction methods in Python code should **always** be reviewed in depth! 

This means:
* Check if the code uses defence in-depth measures for extracting files. 

* Check if the files that will be extracted by the Python code can be assumed secure, so not tampered with. If not: validate if enough additional mitigation measurements are in place when using this code. 

Mitigation measurements are always context dependent, and can be e.g. running the Python program in an isolated environment.
:::

## Preventive measures

Never extract archives from untrusted sources without prior inspection. It is possible that files are created outside of path, e.g. members that have absolute filenames starting with `"/"` or filenames with two dots `".."`.

Make sure a proper `filter` is set:
```
TarFile.extractall(path='.', members=None, *, numeric_owner=False, filter=None)
```
The filter argument specifies how members are modified or rejected before extraction. So set minimal `filter='data'` to prevent the most dangerous security issues, and read the Extraction filters section documentation for details.


* Do not pass filter="tar" or filter="data" for untrusted archives.
If you must unpack, force filter="none" and run in a dedicated, non-privileged container/VM.

:::{note} 
This validation test requires **always** human inspection if the construct is detected.
No automatic test can give you enough confidence! So **no AI agent or other GenAI thing** will help you. 

Using this construct is fine, but make sure you known how to prevent disasters!
:::

## More info

* [CVE-2025-4330](https://www.cve.org/CVERecord?id=CVE-2025-4330)
* [CVE-2024-12718](https://nvd.nist.gov/vuln/detail/CVE-2024-12718)
* [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
* https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter 
* [What Is The Tarfile Vulnerability in Python?](https://www.securitycompass.com/kontra/what-is-the-tarfile-vulnerability-in-python/) 
* [Summary of Python tarfile Infinite Loop Vulnerability (CVE-2025-8194)](https://zeropath.com/blog/cve-2025-8194-python-tarfile-infinite-loop)
* [Tarfile: Exploiting the World With a 15-Year-Old Vulnerability](https://www.trellix.com/blogs/research/tarfile-exploiting-the-world/)