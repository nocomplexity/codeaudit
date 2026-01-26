# Path Module Use

The pathlib module offers classes representing filesystem paths with semantics appropriate for different operating systems.

Using `Path.open()` from the `pathlib` module is generally the modern, "Pythonic" way to handle files. However, like any file operation, it becomes a security liability when it interacts with untrusted user input. Use of Path objects can be insecure—not because the method itself is inherently unsafe, but because of how it is implemented.

Many software systems read and write files based on user input. If the software does not safely check or clean these file paths, an attacker can trick it into reading files that should never be exposed. The most common vulnerability is Path Traversal (also known as Directory Traversal).

Use of `Path` objects can be insecure — but only because of how it’s used, not because the method itself is unsafe.



**Python Code Audit** checks on:
- `Path.open`
- `Path.read_text`
- `Path.read_bytes`

The `pathlib.Path` methods `open()`, `read_text()`, and `read_bytes()` are convenient abstractions for file I/O. However, when used improperly—especially with untrusted or partially trusted input—they can introduce security weaknesses. Static Application Security Testing (SAST) tools should therefore flag and review their usage.


Why **Python Code Audit** Checks for These Usages:

- They are file system access sinks that can be exploited when combined with untrusted input.

- They frequently appear in path traversal, data exposure, and DoS vulnerabilities.

- The methods are concise and high-level, making it easy for developers to overlook validation and boundary checks.


## Use of `Path.open`

Potential Danger:
- **Path Traversal**: If the path is constructed from user-controlled input, attackers may use sequences like `../` to access files outside the intended directory.
- **Unauthorized File Access**: Opening files without proper validation can allow reading or writing of sensitive system or application files.
- **Race Conditions (TOCTOU)**: Checking permissions or file existence before opening the file can lead to time-of-check to time-of-use vulnerabilities.
- **Improper File Modes**: Using write or append modes (`"w"`, `"a"`, `"+"`) may overwrite or corrupt critical files if the path is not strictly controlled.

Mitigation Measures:
- Validate and normalize paths before opening them.
- Restrict file operations to a known safe base directory.
- Avoid constructing paths directly from untrusted input.
- Use least-privilege file permissions and avoid unnecessary write access.



```python
from pathlib import Path

# Vulnerable example
user_input = "../../etc/passwd"
path = Path(user_input)
with path.open("r") as f:
    data = f.read()

# Safer example
base_dir = Path("/app/data").resolve()
path = (base_dir / user_input).resolve()
if base_dir in path.parents:
    with path.open("r") as f:
        data = f.read()

```

## Use of `Path.read_text`:

Potential Danger
- Unrestricted File Read: Reads the entire file content into memory, which can expose sensitive data if the path is attacker-controlled.

- Denial of Service (DoS): Large files may cause excessive memory usage.

- Implicit Trust in Encoding: Automatically decoding text may trigger unexpected behavior or errors if file contents are malicious or malformed.

Mitigation Measures

- Ensure the path refers only to allowed files or directories.

- Enforce file size limits before reading.

- Explicitly handle encoding and errors.

- Avoid using with untrusted or user-supplied paths without validation.

```python
# Vulnerable example
config_path = Path(user_input)
config = config_path.read_text()

# Safer example
allowed_file = Path("/app/config/settings.conf")
config = allowed_file.read_text(encoding="utf-8", errors="strict")
```

## Use of `Path.read_bytes`:

Potential Danger

* Sensitive Binary Data Exposure: May allow attackers to read private keys, credentials, or other binary secrets.

* Memory Exhaustion: Reads the entire file into memory, making it risky for large or unknown file sizes.

* Unvalidated Input Paths: Same path traversal and unauthorized access risks as other file operations.

Mitigation Measures

* Restrict readable files to a fixed set or directory.

* Check file size before reading into memory.

* Prefer streaming reads for large binary files.

* Never allow untrusted input to directly control file paths.

```python
# Vulnerable example
binary_data = Path(user_input).read_bytes()

# Safer example
safe_dir = Path("/app/uploads").resolve()
file_path = (safe_dir / user_input).resolve()
if safe_dir in file_path.parents and file_path.stat().st_size < 10_000_000:
    binary_data = file_path.read_bytes()
```


## More information

* https://docs.python.org/3/library/pathlib.html 
* [CWE-73: External Control of File Name or Path](https://cwe.mitre.org/data/definitions/73.html)