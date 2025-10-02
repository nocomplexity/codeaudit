# Why Security Testing 

Static Application Security Testing (SAST) is crucial for securing Python applications.
SAST testing helps proactively identify vulnerabilities directly in the source code. 

Python Static Application Security Testing (SAST) offers significant advantages by analyzing source code directly.



:::{admonition} Advantages of Security Testing(SAST) on Python code
:class: tip, dropdown


| **Benefit**             | **Description** |
|--------------------------|-----------------|
| [Shift Security Left](https://nocomplexity.com/documents/simplifysecurity/shiftleft.html) ⚙️   | Catches vulnerabilities early in the Software Development Lifecycle (SDLC). |
| Save Time and Cost 💰    | Fixing flaws during the coding phase is far cheaper and faster than costly post-release patches or emergency fixes in production. |
| Automate Checks 🤖       | SAST is easily integrated into CI/CD pipelines to automatically validate the security of new code changes, ensuring continuous security. |
| No Runtime Needed 🔎     | The source code is analyzed without execution, eliminating the risk of running potentially malicious or flawed code during the test. |
| Reduce Attack Surface 🛡️ | Systematically identifies and helps eliminate exploitable code paths, significantly reducing the vulnerability surface that hackers can target. |
| Improve Code Quality ✨  | Encourages developers to adhere to secure coding standards. |
| Support Compliance 📜    | Simplifies alignment with mandatory security rules and regulations, such as PCI DSS, HIPAA, and ISO standards, by providing documented evidence of security testing. |
| Actionable Reporting 📝  | Generates clear, developer-friendly reports that pinpoint the exact location of the possible issue and include remediation guidance. |
| Build Customer Trust ⭐  | Releasing applications with rigorously tested security leads to stronger reliability and greater confidence from users and stakeholders. |
:::

```{admonition} Risks of Skipping security testing(SAST) on Python code
:class: danger, dropdown


| ✔️ Advantages with SAST                 | ❌ Risks Without SAST |
|-----------------------------------------|-----------------------|
| Catch vulnerabilities early in development | Security flaws discovered only after deployment |
| Save time & reduce remediation costs | Fixing issues post-release is expensive and disruptive |
| Shift security left in the SDLC | Security treated as an afterthought |
| Improve code quality with secure standards | Codebase grows with technical debt |
| Automate checks and scans | Manual reviews are inconsistent and time-consuming. Only vulnerabilities that are known by the reviewer are taken into account. However, the number of possible vulnerabilities is large and continuously growing. |
| Detect a wide range of vulnerabilities | Many risks remain invisible until exploited. |
| Python-specific analysis for accuracy | Generic tools miss Python idioms and constructs |
| No runtime required for scanning | Vulnerabilities appear only during execution |
| Easy for CI/CD pipeline integration | Security slows down release cycles |
| Consistent enforcement of policies | Developers apply ad-hoc, inconsistent practices |
| Easier compliance support | Increased risk of regulatory non-compliance |
| Reduce attack surface proactively | Hackers exploit weak, untested code |
| Teach secure coding practices | Knowledge gaps persist in the team |
| Streamline penetration testing efforts | Pen testers waste time on basic issues |
| Reduce technical debt | Complexity and vulnerabilities pile up |
| Build customer trust & confidence | Loss of reputation and user trust after breaches |


```

While Python is often considered a secure language, also Python applications are susceptible to common security flaws, and SAST is a crucial, cost-effective method to address them before deployment.

:::{note} 
Static application security testing(SAST) for python source code is a MUST!

1. To prevent security issues when creating Python software and
2. To inspect downloaded Python software (packages, modules, etc) before running.
:::


Python is one of the most used programming language to date. Especially in the AI/ML world and the cyber security world, most tools are based on Python programs. 

Large and small businesses use and trust Python to run their business. Python is from security perspective a **good** choice. However even when using Python the risk on security issues is never zero.

When creating solutions practicing [Security-By-Design](https://nocomplexity.com/documents/securitybydesign/intro.html) to prevent security issues is too often not the standard way-of-working. 

:::{warning} 
Creating secure software by design is not simple. 
:::


When you create software that in potential will be used by others you **MUST** take security into account.

:::{tip} 
Static application security testing (SAST) tools , like this [**Python Code Audit**](https://nocomplexity.com/codeaudit/) program **SHOULD BE** used to prevent security risks or be aware of potential risks that comes with running the software.

:::

 
[**Python Code Audit**](https://nocomplexity.com/codeaudit/)  is specifically designed for Python codebases. It is tailored to Python’s syntax and unique constructs, enabling it to identify potential security issues effectively.

The **Python Code Audit** SAST tool is an advanced security solution that automates the review of Python source code to identify potential security vulnerabilities."

At a function level, Python Code Audit makes use of a common technique to scan the Python source files by making use of **'Abstract Syntax Tree(AST)'** to do in-depth checks on possible vulnerable constructs. 


Simple good cyber security is possible by [Shift left](https://nocomplexity.com/documents/simplifysecurity/shiftleft.html). By detecting issues early in the SLDC process the cost to solve potential security issues is low. 



