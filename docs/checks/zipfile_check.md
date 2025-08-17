# Check on zipfiles extraction

When using the Python module `zipfile` there is a risk processing maliciously prepared `.zip files`. This can availability issues due to storage exhaustion. 


Validations are done on `zipfile` methods:
* `.extractall`
* `.open` and more.

And `gzip` methods:
* `gzip.open`

## Gzip potential danger
When using `gzip.open` the potential security issue is related to resource consumption if the file is untrusted.

This can lead to:
* **Denial of Service via Resource Exhaustion**
If a gzip file is controlled by a malicious user, they could create a highly compressed file that expands to an enormous size when decompressed. This is known as a "zip bomb."

Such `gzip` file could quickly consume all of the system's available RAM, causing the application to crash or the server to become unresponsive. This is a common attack vector when processing user-uploaded or external compressed files.

* **Potential Path Traversal**
A path traversal vulnerability could arise if the file in the `gzip` file is constructed from user input. For example, if the path came from a web request, a user could provide a path like ../../../../etc/passwd.gz to access sensitive files outside of the intended directory. This is a critical security consideration for any code that handles file paths based on external data that is decompressed with `gzip.open`.

## More information

* https://docs.python.org/3/library/zipfile.html#zipfile-resources-limitations
* https://docs.python.org/3/library/gzip.html