# Development

## Overview

Great that you’re here at this section and want to contribute with code improvement!

:::{admonition} Be sure to check out our Code of Conduct
:class: note
This project values respect and inclusiveness, and enforces a [Code of Conduct](CoC-label) in all interactions. This to ensure that our online spaces are enjoyable, inclusive, and productive for all contributors.


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

Python Code Audit has separate modules with some intentional code duplicity. 

:::{tip}
Consult the **Python Code Audit** [Architecture Overview](architecture) to learn more about the principles that drive our development process.

:::

To lower the barrier for new contributors, I'd make the tone more welcoming, reduce unnecessary wording, and make the steps easier to follow. Here's a revised version in MyST/Markdown:

## Getting Started

Welcome! This guide will help you set up a local development environment for Python Code Audit and start contributing to the project.

### 1. Clone the repository

We recommend working in a dedicated virtual environment to avoid conflicts with other Python projects.

The Python Code Audit source code is hosted on GitHub.


```bash
git clone https://github.com/nocomplexity/codeaudit
cd codeaudit
```

### 2. Install development dependencies

Install `pytest`, which is used for running the test suite:

```bash
pip install pytest
```

### 3. Install Hatch

We use [Hatch](https://hatch.pypa.io/latest/) for packaging and testing across multiple Python versions. Hatch helps create reproducible builds and simplifies development workflows.

Install Hatch with:

```bash
pip install hatch
```

### 4. Install Jupyter Book

The project documentation is built with [Jupyter Book](https://jupyterbook.org/) version 1.

Install it with:

```bash
pip install "jupyter-book<2"
```

To build the documentation:

```bash
cd docs
jb build .
```

If you have changed the table of contents or want to rebuild all example notebooks (for example, before creating a release), run:

```bash
jb clean .
jb build .
```

Some sections of the documentation are generated from Jupyter notebooks, so a clean rebuild is occasionally required.

### 5. (Optional) Install JupyterLab

[JupyterLab](https://jupyterlab.readthedocs.io/) is useful for exploring the API and running the example notebooks included in the documentation.

```bash
pip install -U jupyterlab
```

### 6. Run the test suite

Before making changes, verify that all tests pass in your local environment.

Run the standard test suite with:

```bash
cd tests
pytest -v
```

To test across all supported Python environments, use Hatch:

```bash
hatch test --all
```

If all tests pass, you're ready to start contributing.



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


`Hatch` is used for packaging. By default [`Hatch`](https://hatch.pypa.io/latest/config/build/#reproducible-builds) supports [reproducible builds](https://nocomplexity.com/documents/securityarchitecture/prevention/reproduciblebuilds.html#reproducible-builds).


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


## Building the documentation

To ensure the contribution process is straightforward, the source documentation material is written in Markdown ([MyST](https://mystmd.org/)) and the manual itself is built using the excellent Jupyter Book(**version 1!**) toolchain. Jupyter Book (version 1) uses Sphinx as its core engine to transform notebooks and Markdown into structured websites.

A significant advantage of this setup is that edit suggestions or issues can be made on a per-page basis, without requiring developer knowledge of Git or version control.

To create the documentation, install Jupyter Book **version 1**:
```
pip install "jupyter-book<2"
```

Switch to the ../codeaudit/docs/ directory and run:
```bash
jb build .
```

You can now view the documentation locally and, if required, host it within your own secure perimeter—for example, when adding sensitive instructions for your security team. Hosting the documentation is easy: as these are static HTML files, no dedicated web server is required.

Note: As parts of the documentation are notebooks, it is recommended to install JupyterLab:
```
pip install -U jupyterlab
```

## Developing Plugins

With `Python Code Audit` it is easily possible to develop your own plugin for e.g. `dango`, `tensorflow` or any complex Python library that does not enforce [security-by-design](https://nocomplexity.com/documents/securitybydesign/intro.html) guidelines for external API usage. Check the [APIs](apidocs/modules).

