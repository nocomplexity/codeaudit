# Why Security testing on code

:::{note} 
Static application security testing(SAST) for python source code is a MUST!

1. To prevent security issues when creating Python software and
2. To inspect downloaded Python software (packages, modules, etc) before running.
:::


Python is for one of the most used programming language to date. Especially in the AI/ML world and the cyber security world, most tools are based on Python programs. 

Large and small businesses use and trust Python to run their business. Python is from security perspective a **good** choice. However even when using Python the risk on security issues is never zero.

When creating solutions practicing [Security-By-Design](https://nocomplexity.com/documents/securitybydesign/intro.html) to prevent security issues is too often not the standard way-of-working. 

:::{warning} 
Creating secure software by design is not simple. 
:::


When you create software that in potential will be used by others you **MUST** take security into account.

:::{tip} 
Static application security testing (SAST) tools , like this `codeaudit` program **SHOULD BE** used to prevent security risks or be aware of potential risks that comes with running the software.

:::


This `codeaudit` SAST tool is an advanced tool to automate reviewing source code of Python software to identify sources of potential security issues.

At a function level, `codeaudit` makes use of a common technique to scan the `python` source files by making use of 'Abstract Syntax Tree' to do indepth checks of in potential vulnerable constructs. 

The tool scans the entire `python` source code of a file. Dynamic application security testing(DAST) covers execution of software and is a crucial different technique. DAST testing is done latter in the SLDC process. 

Simple good cyber security is possible by [Shift left](https://nocomplexity.com/documents/simplifysecurity/shiftleft.html). By detecting issues early in the SLDC process the cost to solve potential security issues is low. 



