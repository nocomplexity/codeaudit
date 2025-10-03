# OS System calls 

:::{danger} 
Be suspicious when direct system calls `os.*` are used in a Python program.
:::


*Never trust always verify!* 

So direct systems calls from a Python program **SHOULD** always be verified. System calls can be major security risk. But are nice and easy to use. So often these calls are used. But not always in the correct way!

`codeaudit` checks on:
*  `os.system` : A nice command to execute OS things are malware in a subshell.
* os.execl(path, arg0, arg1, ...)
* os.execle(path, arg0, arg1, ..., env)
* os.execlp(file, arg0, arg1, ...)
* os.execlpe(file, arg0, arg1, ..., env)
* os.execv(path, args)
* os.execve(path, args, env)
* os.execvp(file, args)
* os.execvpe(file, args, env)
* `os.fork`
* `os.write`
* `os.writev`
* and more!

These functions all can execute a new program, replacing the current process; they do not return. On Unix, the new executable is loaded into the current process, and will have the same process id as the caller.

:::{tip} 
When shell commands are used, make sure you understand possibly security consequences. Besides malware most common is that the availability is at risks when file systems are filled with files or logfiles.
:::


## Why `os.write` can be Vulnerable: File Descriptor Mismanagement

The vulnerability of the `os.write(fd, data)` function in Python stems not from the function itself, but from its **low-level interaction with file descriptors (FDs)**, which bypasses standard, safer I/O abstractions. 
The function writes raw bytes directly to a numerical file descriptor `fd`.

The primary risk is the use of an **unvalidated or attacker-controlled file descriptor (FD)**. This can lead to severe security and stability issues:


1. Data Corruption and Integrity Compromise 💾

If an attacker can control the `fd` argument, they could redirect the output to an unintended file:

* **Sensitive File Overwriting:** Writing to critical system files (e.g., configuration files like `/etc/passwd` or `/etc/shadow`, log files, or application binaries) can **corrupt system integrity** or **allow privilege escalation** if the data contains malicious commands or changes authentication data.
* **Arbitrary File Write:** The attacker can potentially **overwrite any file** the process has write permissions for.


2. Information Leakage and Data Injection ✉️

File descriptors aren't just for disk files; they can also point to **sockets, pipes, or other inter-process communication (IPC) channels**.

* **Inter-Process Data Injection:** Writing to a pipe or socket `fd` used by another process can **inject arbitrary, unvalidated data** into that process's data stream. For example, injecting malicious commands into a shell session or corrupted data into a communication stream.


3. Denial of Service (DoS) 🛑

Mismanagement of FDs can directly impact system stability or resource availability.

* **Resource Exhaustion:** If `fd` points to a device or a pipe that is not being read, excessive writes can fill up buffers, causing the application or system to hang or crash due to resource exhaustion.
* **Service Interruption:** Writing gibberish to an active and expected stream can immediately crash or hang the receiving application, causing a **denial of service**.


### Preventive measures


Always ensure that file descriptors used with $\mathtt{os.write}$ are **validated** and **tightly controlled**. It is generally safer to use Python's built-in file handling (e.g., the $\mathtt{open()}$ function and $\mathtt{file.write()}$ method), which operates at a higher level of abstraction and typically includes more robust error and permission handling.


## More information

* https://docs.python.org/3/library/os.html#os.popen
* https://cwe.mitre.org/data/definitions/78.html
* [Python Fork Bomb](https://medium.com/@BuildandDebug/python-fork-bomb-a-one-liner-that-can-crash-your-system-652540c7d89f)
* [Fork bomb attack (Rabbit virus)](https://www.imperva.com/learn/ddos/fork-bomb/)