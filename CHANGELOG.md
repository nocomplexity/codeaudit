# Change Log

# Version 1.2: Changes and Updates

* fix: Improved error handling — when performing a file scan on a single Python file that cannot be parsed, the CLI now correctly displays an error message.

* fix: Updated API logic to properly handle parsing errors for single Python files.

* fix: Corrected validation descriptions for `os.write` and `os.writev`. Writing to unvalidated or unintended file descriptors can lead to data corruption, privilege escalation, or denial of service.

* fix: Internal API functions now use a leading underscore (`_`) to clearly distinguish them from public APIs.

* **new**: Added a function for weakness visualization. Refer to the examples for usage details.

* **new**: Added API documentation and examples for usage details.


## Version 1.1:What's New

We've released a new version with several key improvements focused on making your security workflow smoother and providing more detailed security information.

* Streamlined Scanning:

The separate `directoryscan` command has been removed. You can now use the versatile `filescan` command to scan both individual files and entire directories. This simplifies the command-line interface and makes the process more intuitive.

* Enhanced Reporting:

We've made minor corrections to the documentation and static HTML reports to improve clarity. Additionally, warning messages are now more descriptive, helping you quickly understand potential issues.

* Improved Vulnerability Data:

You'll now get more detailed information about module vulnerabilities. The tool now includes CVSS scores, a standard metric for rating vulnerability severity, giving you a clearer picture of the risks.

* Behind-the-Scenes Fixes:

We've made a more robust and reliable adjustment to how the tool retrieves file names. This ensures consistency and accuracy during scans. We've also added beta-level API functions, opening up new possibilities for integration.



## Version 1.0

This release represents a stabilisation of Python Code Audit!
Main changes in relation to the pre-1.0 versions are:
* More validations added: Python Code Audit now counts 70 security validations!
* Documentation updates
* Improved validation for `builtins`, like `compile`, `exec`,, `eval` that can be obfuscated in code. 
* Various UI/UX updates. CLI text improved and HTML report text made consistent. 
* Added test to validate correct working for now and in the future. Also validated working with other SAST tools to make sure core functionality is rock solid or better! Spoiler Python Code Audit is better than most used OSS and commercial SAST tools available today!


## Beta Versions (Before 1.0)

All published beta version are stable and verified!
During the public beta phase input of users and experts is retrieved. 
This resulted is mainly:
* More validation
* Better documentation and
* UI/UX improvements to make sure Python Code Audit is dead simple to use for non-programmers to validate a Python package.

