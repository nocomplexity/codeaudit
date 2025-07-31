# Using TarFile statement

Code Audit checks on the use of:
* `TarFile.extract` and
* `TarFile.extractall`

:::{danger} 
Using `TarFile.extractall` or `TarFile.extract` is dangerous.
Always. So good mitigation measurement **must** be present in the code!
:::



Never extract archives from untrusted sources without prior inspection. It is possible that files are created outside of path, e.g. members that have absolute filenames starting with "/" or filenames with two dots "..".

Make sure a proper `filter` is set:
```
TarFile.extractall(path='.', members=None, *, numeric_owner=False, filter=None)
```
The filter argument specifies how members are modified or rejected before extraction. So set minimal `filter='data'` to prevent the most dangerous security issues, and read the Extraction filters section documentation for details.

:::{note} 
This validation test requires **always** human inspection if the construct is detected.
No automatic test can give you enough confidence! So **no AI agent or other GenAI thing** will help you. 

Using this construct is fine, but make sure you known how to prevent disasters!
:::

## More info

* https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter 
