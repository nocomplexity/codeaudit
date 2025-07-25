# Why Security testing on code

Static Application Security Testing (SAST) for Python is a **MUST**.

:::{note} 
Static application security testing(SAST) for python source code is a MUST:
1. Prevent security issues when creating Python software.
2. Inspect Python code (packages, modules, etc) from other before running.
:::


Python is for one of the most used programming language to date. Especially in the AI/ML world and the cyber security world, most tools are based on Python programs. This is a consequence of the fact that the Python programming language is simple use for problem solving. And programming is fundamentally about problem-solving. 

Large and small businesses use and trust Python to run their business. Python is from security perspective a **good** choice. However even when using Python the risk on security issues is never zero.

When creating solutions for problems creating new cyber security problems is never on the list. But creating secure software is not simple. 

So when you create software that in potential will be used by others and will be run on different systems than yours **MUST** take security into account.

Static application security testing (SAST) tools , like this `codeaudit` program **SHOULD BE** used to prevent security risks or be aware of potential risks that comes with running the software.

This `codeaudit` SAST tool is an advanced tool to automate reviewing source code of Python software to identify sources of potential security issues.

At a function level, `codeaudit` makes use of a common technique to scan the `python` source files by making use of 'Abstract Syntax Tree' to do indepth checks of in potential vulnerable constructs. 

The tool scans the entire `python` source code of a file. Dynamic application security testing(DAST) covers execution of software and is a crucial different technique. DAST testing is done latter in the SLDC process. 

Simple good cyber security is possible by [Shift left](https://nocomplexity.com/documents/simplifysecurity/shiftleft.html). By detecting issues early in the SLDC process the cost to solve potential security issues is low. 



