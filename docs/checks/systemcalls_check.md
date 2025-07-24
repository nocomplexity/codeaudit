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
* and more!

These functions all can execute a new program, replacing the current process; they do not return. On Unix, the new executable is loaded into the current process, and will have the same process id as the caller.

:::{tip} 
When shell commands are used, make sure you understand possibly security consequences. Besides malware most common is that the availability is at risks when file systems are filled with files or logfiles.
:::



## More information

* https://docs.python.org/3/library/os.html#os.popen
* https://cwe.mitre.org/data/definitions/78.html
* [Python Fork Bomb](https://medium.com/@BuildandDebug/python-fork-bomb-a-one-liner-that-can-crash-your-system-652540c7d89f)
* [Fork bomb attack (Rabbit virus)](https://www.imperva.com/learn/ddos/fork-bomb/)