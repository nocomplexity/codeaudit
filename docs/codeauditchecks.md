# Command `codeaudit checks`

The `codeaudit checks` command creates a report with all security validation implemented for that are used for the `filescan` scan command. 


To use the `codeaudit checks` feature type in the console:

```
codeaudit checks
```

This will generate a HTML report, including the version of Python Code Audit that is installed.

All implemented static security validations can be found [here](examples/codeauditchecks.html).

:::{attention} 
Always use the latest version to have the latest security validations!

Update your local installation with:
```bash
pip install -U codeaudit
```
