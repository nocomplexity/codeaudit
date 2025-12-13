# Zipfiles extraction

When using the Python module `zipfile` there is a risk processing maliciously prepared `.zip files`. This can availability issues due to storage exhaustion. 


Validations are done on `zipfile` methods:
* `.extractall`
* `.open` and more.

And the methods:
* `gzip.open`
* `bz2.open`
* `bz2.BZ2File` 
* `lzma.open` 
* `lzma.LZMAFile` 
* `shutil.unpack_archive`
* `compression.zstd.decompress`
* `compression.zstd.open`

## Potential danger when opening compressed files

When using `gzip.open` or equivalent the potential security issue is related to resource consumption if the file is untrusted.

:::{caution} 
Never extract archives from untrusted sources without prior inspection! 

It is possible that files are created outside of the path specified in the extract_dir argument, e.g. members that have absolute filenames starting with “/” or filenames with two dots “..”.

:::


This accounts also for using `bz2`, `lzma` , `shutil.unpack_archive`,  `tar` or `zstd` compressed files. All these great Python functions that can decompress files require defense in depth to be sure that only trusted files can be opened.

This can lead to:
* **Denial of Service via Resource Exhaustion**
If a gzip file is controlled by a malicious user, they could create a highly compressed file that expands to an enormous size when decompressed. This is known as a "zip bomb."

Such `gzip` file could quickly consume all of the system's available RAM, causing the application to crash or the server to become unresponsive. This is a common attack vector when processing user-uploaded or external compressed files.

* **Potential Path Traversal**
A path traversal vulnerability could arise if the file in the `gzip` file is constructed from user input. For example, if the path came from a web request, a user could provide a path like ../../../../etc/passwd.gz to access sensitive files outside of the intended directory. This is a critical security consideration for any code that handles file paths based on external data that is decompressed with `gzip.open`.

## Possible measures

1. Make sure by design that these Python functions  will  **Only decompress files from trusted sources** 

2. Set a limit for the  decompression size. This is not simple and always possible! The Python `lzma` library does not have a built-in parameter to do this directly. You would need to read the data in fixed-size chunks and check the total size as you go, raising an error if it exceeds a predefined limit.

3. Check File Metadata: If possible, check the uncompressed size of the file from its header before starting the decompression. While not all formats contain this information, it can be a useful first check. **Note: This mitigation measurement should NEVER be used without other safeguards**

4. Resource Monitoring: Monitor your application's memory,  CPU and resource usage during the decompression process and terminate it if it begins to consume an unusual amount of resources. Note that this measurement is not fail-safe!

## More information

* https://docs.python.org/3/library/zipfile.html#zipfile-resources-limitations
* https://docs.python.org/3/library/gzip.html
* https://docs.python.org/3/library/bz2.html#bz2.open
* https://docs.python.org/3/library/shutil.html
* [PEP 784 on zstd](https://peps.python.org/pep-0784/)
* [CWE-409: Improper Handling of Highly Compressed Data (Data Amplification)](https://cwe.mitre.org/data/definitions/409.html)
* [urllib3 Streaming API improperly handles highly compressed data](https://www.cve.org/CVERecord?id=CVE-2025-66471)