# Development

## Overview

Great that you’re here at this section and want to contribute with code improvement!

:::{admonition} Be sure to check out our Code of Conduct
:class: note
This project values respect and inclusiveness, and enforces a [Code of Conduct](CONTRIBUTE.md#code-of-conduct) in all interactions. This to ensure that our online spaces are enjoyable, inclusive, and productive for all contributors.


We adopt the [Collective Code Construction Contract(C4)](https://rfc.zeromq.org/spec/42/) to streamline collaboration. C4 is meant to provide a reusable optimal collaboration model for open source software projects. 
:::

:::{important} 
When you contribute text or code to Python Code Audit, your contributions are made under the same license as the file you are working on. 
:::

:::{tip}
All contributions are welcome!
Think of corrections on the manual, code and more, or better tests.

* Questions, Feature Requests, Bug Reports should all be reported on the [Github Issue Tracker](https://github.com/nocomplexity/codeaudit/issues) .

* [Black](https://black.readthedocs.io/en/stable/index.html) is used for code style. But for a simple fix, using `Black` is not required!

:::

Python Code Audit has separate modules with some intentional code duplicity. The architecture view for Python Code Audit is:
![PCA_architecture](pca_overview.png)

## Getting started
To get started with Python Code Audit’s codebase, take the following steps:

1. Clone and install the package

The **Codeaudit** code repository is hosted at [Github](https://github.com/nocomplexity/codeaudit).

```bash
git clone https://github.com/nocomplexity/codeaudit 
cd codeaudit
```
2. Install the required development packages

```bash
pip install pytest
```

3. Run the tests

For all code tests, Python Code Audit uses `pytest`. 

Before making changes, make sure all the tests run **OK**! 

Running tests is done with:

```bash
cd /tests
pytest -v 
```

## Development Guidelines

:::{warning}
This simple tool is designed to be simple to use and maintain.

Rationale: Tools that should be trusted for security should avoid code complexity. 
:::


* [Black](https://black.readthedocs.io/en/stable/index.html) is used for code style. But for a simple fix, using `Black` is not required!

:::{tip} 
Before submitting a pull request or starting with coding: 

Get in contact with the developers! The most simple way is to report the feature or bug you want to solve on the [Github Issue Tracker](https://github.com/nocomplexity/codeaudit/issues).

:::



The **Python Code Audit** tool is designed using the [Zero Complexity By Design principles](https://nocomplexity.com/documents/0complexity/abstract.html). So the goal is to keep the tool simple to use and the **code** simple to adjust or to extend.

`Python Code Audit` is developed as a local first solution. CICD integration (local or with a Cloud based solution) is easily possible with the APIs in various forms.

Before submitting a pull request, make sure all tests run **OK** again.

:::{warning} 
Not all pull requests with new features will be accepted, this to keep Python Code Audit **simple**. 
:::

### Testing
Python Code Audit takes quality very seriously. So Python Code Audit has tests on features, edge cases, and real-world examples. 

This means:
* Every security validation has a test case.
* Crucial parts of the code have a regression test. This to make sure that changes somewhere in the code can not be inserted silently without testing the core functionality.
* External APIs are tested to make sure API changes do not pass silently.


Every test is self-validating using assertions and fails with an error if the output isn’t exactly as expected.

The Python Code Audit Security validations that are implemented are not invented in isolation. Some reference tests also executed with other SAST scanners.


## Developing Plugins

With `Python Code Audit` it is easily possible to develop your own plugin for e.g. `dango`, `tensorflow` or any complex Python library that does not enforce [security-by-design](https://nocomplexity.com/documents/securitybydesign/intro.html) guidelines for external API usage. 

