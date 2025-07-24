# Check on zipfiles extraction

When using the Python module `zipfile` there is a risk processing maliciously prepared `.zip files`. This can availability issues due to storage exhaustion. 

Validations are done on:
* `.extractall`
* `.open` and more.


More information:

* https://docs.python.org/3/library/zipfile.html#zipfile-resources-limitations