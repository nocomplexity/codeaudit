# Solve security issues 

Python Code Audit scans and checks for **potential security issues**. A potential security issue is a weakness that **can** lead to a security vulnerability with impact.

There is an important difference between a **potential security issue** and a **security vulnerability** in Python code:

:::{important} 
A **potential security issue** or weakness is a general flaw, error, mistake or sloppy programming habit in a programs design, implementation, or operation that could lead to security problems. It's a potential area of concern that might not be immediately exploitable but increases the risk of a vulnerability emerging. 

Depending on the **context** where a Python program is executed, found security issues should be fixed, or can be neglected. 

:::

Examples of **potential security issues** or weaknesses that Python Code Audit discovers:
* Risks of running untrusted code by using Python statements that allow this. Think of `compile`, `eval` or `exec`.
* Availability risks. Operating systems functions that can create directories or files can cause availability risks.
* Risks of changing permission on files or directories. Python files are too often run with too broad permissions. This can lead to severe risks on data leakage or integrity issues on files.

See [section `command codeaudit checks`](codeauditchecks) to get more insight on implemented security validations.

Issues in Python code are not necessarily directly exploitable on their own, but detected security issues are a fertile ground for vulnerabilities to appear.


A vulnerability is an exploitable weakness. So minimize the risks for vulnerabilities and take the reported **potential security issues** serious.

:::{danger} 
If a weakness in Python code exists, and **if** a method is found to take advantage of that weakness to cause harm, then it becomes a vulnerability. 

Addressing weaknesses [proactively](https://nocomplexity.com/documents/simplifysecurity/shiftleft.html#shift-left) helps prevent vulnerabilities from emerging, while patching vulnerabilities reactively addresses known exploitable flaws.
:::

## How to solve security issues


:::{tip} 
If you are not a programmer but need advice on reported issues, the urgent advice is to get expert advice!
Cyber security is difficult. It requires expertise of many different areas. So Python knowledge and experience is needed, but also in-depth knowledge on security.
Check whether one of our [sponsors](sponsors) have the capability to help you!
:::

If you are a developer:
1. Make sure you **understand** why Code Audit reported an issue. 
2. Adjust the code or add a comment at the code why the code line is no security issue. Or even better: Adjust your documentation and clearly state what the rationale or measurements are why the issue reported can be neglected.
3. Ask for help if you are not sure! Application security is complex. There will always be risks, but the minimum you can and **MUST** do is to make sure that your Python code is no risk for your users.


If you are a user of a Python program or package:
1. Ask the developer, company what mitigation measurements are taken to report issues. Some issues **SHOULD** always be solved in code, other issue depend on the context of how and where the Python program will be used.
2. If you are dealing with open source software: **DO NOT REPORT THE FINDINGS IN PUBLIC!** Try to contact the maintainers using a private email or check if the project has published how to report possible security issues.
3. Never trust, always verify: Check if and how code is adjusted. Or consult an expert to give you guidance to minimize security risks! See our [sponsor page](sponsors) to find companies who might offer assistance.

:::{tip} 
Only when you are completely certain, and following a thorough **security review of the code and its design**, may you add a security comment. This [marker](markingissues) should indicate that a particular code construct does not constitute a security weakness or threat.

See section [Marking Issues](markingissues).
:::