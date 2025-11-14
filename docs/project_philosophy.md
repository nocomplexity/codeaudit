# Project Philosophy

The rapid growth and increasing complexity of Python-based web applications and systems have made robust security testing more important than ever. 

To strengthen cyber security, we must make protection both **better and simpler** — simpler to use, simpler to maintain, and simpler to understand.

Too often, complex security tools end up **reducing security** rather than improving it. The goal should be to **do the simple things well** — ensuring strong fundamentals rather than adding unnecessary complexity. 

We believe that openly sharing ideas, specifications, and other intellectual property is key to maximizing security innovation and reducing vulnerabilities in Python software components.

Security validation for Python code should be **fast, straightforward, and effective**.


However, there are almost no **high-quality Free and Open Source (FOSS)** Static Application Security Testing (SAST) tools available for Python. 

## Design Approach and Solution


We believe that static security testing of Python code should be carried out more frequently and to a higher standard — but it should also be **extremely simple for everyone** to perform. Whether you’re a professional developer or an occasional Python user, **anyone** should be able to run a SAST test quickly and easily.


Python Code Audit is built on strong design principles:
* **Better be safe than sorry!** **Python Code Audit** takes a defensive security approach. 

* **Local first**: No data leakage and no reliance on third-party services. Security should never be outsourced to a “black box” environment.


* **Simple to use**: Designed for ease of use by anyone, regardless of experience level.


* **Simple to extend**: Easy to adapt and build upon for future needs.


* **Simple to maintain**: We follow [0Complexity design principles](https://nocomplexity.com/documents/0complexity/abstract.html): simplicity enhances security. This means minimising dependencies and keeping both design and implementation straightforward and transparent.


* **Transparent**: All code is released under a FOSS (Free and Open Source Software) [licence](license). Transparency builds trust.


* **Trust is good, but validation is better**: The tool validates against numerous common weaknesses often found in Python code. 

* **Limited scope**: No tool can do everything well. Complex checks such as SQL injection detection, TLS certificate validation, or cryptographic misuse analysis are intentionally out of scope. These areas are difficult to automate reliably and often create a false sense of security. Instead, we focus on delivering a **simple, trustworthy security tool** that performs its defined tasks exceptionally well — without compromise.

* **You are in charge**: No AI agent should decide what is needed — only you fully understand the context. The tool is there to assist, but it remains **your responsibility** to determine whether a weakness could develop into a vulnerability that requires fixing.


## Read our Manifesto

:::{admonition} Cyber security protection can be much better and simpler.
:class: tip
[**Read our Manifesto**](https://nocomplexity.com/simplifysecurity-manifesto/)

:::




