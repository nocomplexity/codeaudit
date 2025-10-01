# Solving security issues 

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


## Dealing with false positives


:::{note} 
Python Code Audit only reports **potential security issues**. 
It is up to the user, developer, security tester or someone with the required **security** and **Python** knowledge to decide if action is needed.

This Python Code Audit SAST tool, but this accounts for all SAST tools, analyze code in isolation. So without the runtime environment or how the any knowledge on how code interacts with other components and who the users are. 

For good security you always need to construct a [threat model](https://nocomplexity.com/documents/securityarchitecture/architecture/threadmodels.html#threat-models) in able to evaluate if potential issues should be resolved.

Despite the rise of AI, no single tool can judge the **context** where a program is used, how it is used and by whom. So if you are in doubt if action on a reported issues is needed, you **SHOULD** contact a security specialist who has deep technical knowledge of cyber security also solid knowledge on developing secure Python programs. In our [section sponsors](sponsors) you find agencies or consultants that can provide the needed assistance. Do not hesitate to get professional help, cyber security is a complex area!
:::

:::{warning} 
DO **NOT** rely on SAST scanners that are powered by AI-agents / LLM systems to solve your cyber security problems!

Most are just far from good enough. 

In the best case scenario, you'll only be disappointed. But the risk of a false sense of security is enormous.
:::




:::{note} 
The static nature of the Python Code Audit SAST scan is that it can’t identify vulnerabilities, but only reports **potential security issues**
:::

Python Code Audit is designed to minimize so called 'false positives`. 


A false positive arises when a static analysis tool falsely claims that a construct in the code is insecure. Python Code Audit has no false positives, it will only reports on **potential security issues**.

Python Code Audit is created for:
* Security researchers
* Users and
* Developers
Every user group has its own requirements and needs. And will review the found issues from a different perspective and context. 


Python Code Audit will **not** detect and report imported modules that are commented out. E.g. in the following file:

```python
"""Sample file for module check"""

import linkaudit #has no data in OSV DB
import pandas #has some minor data in OSV
import requests #has lots of OSV data
#import numpy #has lots of OSV data! (a lot!!) 

import os
import random
import csv

def donothing():
    print('no way!')
    os.chmod('ooooooooooooono.txt',0x777) #this will give an alert on codeaudit filescan!
```

The `numpy` module is not reported on a module check and is not counted in the statistics that Python Code Audit created. This because this module is commented out. Modules that are imported, but not yet used are reported. This because it is likely that the modules will be used in a next iteration of the Python file. And checking as fast as possible on possible security issues for modules that *could* be used makes sense.



:::{note} 
Python Code Audit architecture, design , implementation overcome the shortcoming of many 'legacy' SAST tools who are good at reporting false positives, but lack good validation for correct secure Python use.

:::