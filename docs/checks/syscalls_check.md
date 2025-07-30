# Sys Statements

Code Audit checks on the use of:
*  `sys.call_tracing()`
* `sys.setprofile()`, and 
* `sys.settrace()` 

These are powerful introspection tools often used for debugging, profiling, or tracing. But they can introduce significant security and safety risks if used improperly or maliciously.

:::{admonition} **Avoid using these hooks in production** unless absolutely necessary.
:class: caution
* Use sandboxing (e.g., Jails, (LXC)containers, VMs) to isolate untrusted Python code.
* Disable introspection features for user-submitted code (e.g., in REPLs, notebook servers).
:::


## Potential Security Issues

1. **Code Injection / Execution Monitoring**

* These functions allow **monitoring of arbitrary code execution**, including:

  * Function names, file paths, line numbers, arguments, and stack frames.
  * This can lead to **information leaks**, e.g., capturing credentials, API keys, or sensitive computation paths.

2. **Backdoors or Logging of Sensitive Data**

* A malicious trace or profile function can:

  * **Record user input**, arguments to sensitive functions, return values, etc.
  * **Log passwords**, encryption keys, or internal state.

* Since the hooks have access to the frame object (`frame.f_globals`, `frame.f_locals`), they can **inspect or modify variables**.

3. **Stealthy Surveillance**

* If these hooks are installed early (e.g., via a startup script, plugin, or compromised library), the user may be unaware their code is being **monitored or altered**.

4. **Denial of Service (DoS)**

* Poorly implemented or malicious tracing/profiling functions can:

  * Add significant performance overhead (especially with `line` events).
  * Lead to stack overflows or infinite loops (e.g., by setting a trace inside a trace).
  * Make debugging and execution unreasonably slow or unresponsive.

5. **Tampering with Control Flow**

These module function give access to some variables used or maintained by the Python interpreter and to functions that interact strongly with the interpreter. So:

* In Python, the trace function can **modify the execution environment**, potentially altering how code behaves (e.g., monkey-patching via trace).
* Can be used to **silently bypass security checks** or manipulate outcomes of computations.

6. **Accessing Private/Internal Code**

* Hooks can observe **internal logic of libraries** (even proprietary or obfuscated ones).
* In shared or multi-tenant environments, this can violate **code or data isolation**.

---




## More information

* https://docs.python.org/3/library/sys.html 