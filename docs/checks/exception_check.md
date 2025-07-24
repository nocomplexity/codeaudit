# Exception statements

Codeaudit checks the `onpass` in a except block.

The Python code `try: do_some_stuff() except Exception: pass` presents potential security risks due to its overly broad exception handling and silent failure option.

This also applies when using `continue`!

So Codeaudit also checks on:
*  `pass` and 
* `continue` 
statements in exception clauses.

## Background

Checking exception statements in Python code for possible security issues should be done.
Reasons are e.g.:

1.  **Masking of Critical Errors and Vulnerabilities:**

      * **Hiding Bugs:** This is the most immediate and dangerous risk. Any exception, from a simple `TypeError` to a critical `MemoryError` or a security-related issue like an `InjectionError` (if `do_some_stuff()` interacts with databases or external systems), will be silently caught and ignored. This means that genuine bugs, misconfigurations, or even malicious attempts to exploit the system will not be reported or logged, making debugging and incident response extremely difficult or impossible.
      * **Undetected Attacks:** If an attacker triggers an exception as part of an exploit (e.g., a buffer overflow that causes a specific exception, or an invalid input that leads to an unhandled condition), the `except Exception: pass` block will simply swallow it. The attack might succeed without any indication that something went wrong, allowing the attacker to gain unauthorized access or manipulate data.
      * **Resource Leaks:** If `do_some_stuff()` involves opening files, network connections, or acquiring locks, and an exception occurs before these resources are properly closed or released, the `pass` statement will prevent any cleanup. This can lead to resource exhaustion, denial-of-service (DoS) attacks, or even data corruption if subsequent operations try to use leaked resources.

2.  **Denial of Service (DoS) Vulnerabilities:**

      * **Infinite Loops/Stuck Processes:** If an error within `do_some_stuff()` leads to an infinite loop or a process getting stuck, the `except Exception: pass` won't break out of it or report the issue. The application could become unresponsive, consuming excessive resources and making it vulnerable to DoS attacks.
      * **Ignoring System-Level Exceptions:** `except Exception` catches almost all user-defined exceptions. However, it still allows critical system-exiting exceptions like `SystemExit` (raised when `sys.exit()` is called) and `KeyboardInterrupt` (raised when a user presses Ctrl+C) to propagate. While `except: pass` (a bare except without `Exception`) would catch these and prevent graceful program termination, `except Exception: pass` doesn't, which is good. However, if the intent was to prevent *any* form of termination for some misguided reason, it's a risk. The larger problem is with exceptions that indicate a fundamental system problem that *should* cause a crash, but are swallowed.

3.  **Compromised Data Integrity and Consistency:**

      * If `do_some_stuff()` performs operations that modify data (e.g., database writes, file manipulations), an exception could leave the data in an inconsistent or corrupted state. Silently ignoring the exception means the program continues as if nothing happened, potentially propagating bad data throughout the system, leading to data loss or incorrect results.

4.  **Lack of Forensic Information:**

      * When an exception is silently passed, there is no logging, no traceback, and no indication of what went wrong. This severely hinders post-mortem analysis and incident investigation. If a security incident occurs, having detailed logs of errors and exceptions is crucial for understanding the attack vector, the extent of the damage, and how to prevent future attacks.

5.  **Difficulty in Auditing and Compliance:**

      * For security audits and compliance requirements (e.g., GDPR, HIPAA, PCI DSS), having robust error handling and logging is often a necessity. Code that silently ignores exceptions makes it impossible to demonstrate that errors are being managed appropriately, potentially leading to compliance failures.

## Options to mitigate risks

  * **Be Specific:** Always catch specific exceptions that you anticipate and know how to handle. For example, `except ValueError:` or `except FileNotFoundError:`.
  
  * **Log Exceptions:** Even if you choose not to crash the program, always log the exception with its full traceback. This provides invaluable debugging and forensic information. Use Python's `logging` module.
    ```python
    import logging
    logging.basicConfig(level=logging.ERROR) # Configure logging

    try:
        do_some_stuff()
    except Exception as e:
        logging.error("An unexpected error occurred during do_some_stuff()", exc_info=True)
        # Optionally, re-raise the exception if the program cannot continue meaningfully
        # raise
    ```
  * **Avoid `pass`:** Only use `pass` if the exception is truly expected and handling it means doing nothing, and you have documented why that's the case. Such scenarios are rare.
  * **Use `finally` for Cleanup:** If resources need to be released regardless of whether an exception occurs, use a `finally` block or context managers (`with` statements).
    ```python
    try:
        f = open("my_file.txt", "r")
        # ... do stuff with f ...
    except FileNotFoundError:
        print("File not found!")
    finally:
        if 'f' in locals() and not f.closed:
            f.close()
    ```
    Even better with `with`:
    ```python
    try:
        with open("my_file.txt", "r") as f:
            # ... do stuff with f ...
            pass
    except FileNotFoundError:
        print("File not found!")
    ```
    

## More info

* [CWE-703: Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)
