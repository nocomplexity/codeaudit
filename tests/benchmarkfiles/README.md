# Introduction

A good question for anyone who places trust in cybersecurity tools is: “How good is this tool?” Of course, no tool is perfect. Even AI-powered cyber tools fail in many ways, so human critical thinking about weakness findings, context and any necessary safety improvements should never be outsourced to a tool.

In-depth research to determine whether a simple, reusable benchmark suite was available for Python SAST scanners showed that no single, straightforward, broad default validation suite exists to check the correctness of various Python SAST scanners. I therefore created a standard validation suite to assess the quality of different Python SAST scanners. The results are rather shocking when compared with the quality of [Python Code Audit](https://github.com/nocomplexity/codeaudit). This is partly because [Python Code Audit](https://github.com/nocomplexity/codeaudit) follows a zero-configuration principle and is primarily developed to give a very good and rapid insight into the quality of Python applications and modules written by others.

## What

This SAST benchmark suite was created to validate the correct working of SAST scanners for Python. I also produced a performance benchmark to measure how fast Python Code Audit is, to compare it with other SAST scanners, and to check performance on different platforms. As an impatient security researcher, I maintain that scanning 3,000 valid Python files should be completed within 60 seconds on an average user laptop, without any time spent on configuration of the SAST scan or other time-consuming tasks.

## How to use

Everyone is invited to use and improve this benchmark suite for Python SAST tools. You can use it to validate the correctness of your current SAST tool against Python Code Audit.

Many types of validation are possible when measuring the correctness of Python SAST engines. Preferred improvements to this Python SAST benchmark should remain within the following scope:

* General Python use of built-in constructs or standard Python libraries. Validations specific to external modules (for example sqlite or Django) are out of scope.
* Focused on weaknesses that are Python-specific. Checks such as XSS or secrets detection are not included. While these are relevant for broader security validation, they are not specific Python SAST checks.

If you clone the project, you will find the benchmark files at:

```bash
../codeaudit/tests/benchmarkfiles
```
