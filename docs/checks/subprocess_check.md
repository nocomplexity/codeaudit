# Subprocess Statement

Codeaudit checks the use of Subprocesses in a Python file.

Using the default Python library `subprocess` for Subprocess management is very powerfull.

:::{caution} 
When using the `subprocess` library the Python code can invoke an external executable. 
:::


Python `codeaudit` does not check on `Popen.communicate` This method cannot be directly used on a "foreign" process. It can only work on a launched by subprocess that is created by `Popen` in the same Python script. Popen.communicate() is a method of the Popen object. 

It is good to known that Python's `subprocess` module doesn't provide a mechanism to "attach" to standard I/O streams of an already running process. 

Note that when *old* subprocess functions are used, the severity is high. So avoid using the functions and migratie to `.run` for:
* `subprocess.call`
* `subprocess.Popen` 
* `subprocess.call` 
* `subprocess.check_call` 
* `subprocess.check_output` 
* `subprocess.getoutput` 
* `subprocess.getstatusoutput` 
* `subprocess.run` 

## Rationale

The subprocess module allows Python code to execute external system commands. This is powerful — and dangerous — because it creates a bridge between untrusted input and the operating system shell.

Security vulnerabilities typically arise when:

- User-controlled input is interpolated into command strings

- The shell is invoked (shell=True)

- Arguments are passed as strings instead of lists

- Output or exit codes are trusted without validation

- Errors are ignored or mishandled

If an attacker can influence any part of the command, they may achieve command injection, privilege escalation, data exfiltration, or remote code execution (RCE).

All of the listed APIs are safe by default only if used correctly — but very easy to misuse!


## Preventive measures

Applies to all subprocess APIs listed:

1. Avoid shell=True

- This is the single biggest risk factor.

- Shell metacharacters (;, &&, |, $(), `) become exploitable.

2. Pass arguments as lists, never strings

- `["ls", "-l"]` instead of `ls -l`

3. Never concatenate user input into commands

- Especially paths, filenames, flags, or filters.

4. Validate and sanitize all inputs

- Use allowlists, not blocklists.

5. Check return codes explicitly

- Silent failures can mask partial command execution.

6. Use the least-privileged user possible

- Never run subprocesses as root unless unavoidable.

7. Prefer high-level Python APIs

- Many shell commands have safe Python equivalents (os, pathlib, shutil).

## Example (by API)

### `subprocess.call`

**Why it’s risky**

- Executes commands without raising exceptions
- Return codes are often ignored
- Vulnerable when `shell=True` or when strings are used

**Bad example**
```python
subprocess.call("rm -rf " + user_input, shell=True)
```

Risk:
```bash
user_input = "/tmp/data; rm -rf /"
```


## More information

* https://docs.python.org/3/library/subprocess.html
