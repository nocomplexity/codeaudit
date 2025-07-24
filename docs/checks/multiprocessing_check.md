# Multiprocessing Statement

Code audit checks on the `multiprocessing` `Connection.recv()` statement. Reason: This uses pickle.

So the use of the `multiprocessing` module **always** needs a good design and review!

From a security point of view:
* The Connection.recv() method automatically unpickles the data it receives, which can be a security risk unless you can trust the process which sent the message.

So authentication is needed unless the connection object was produced using Pipe().

Use the `recv()` and `send()` methods from the `multiprocessing` module **only** after performing solid authentication. 

:::{admonition} Notice
:class: note
Codeaudit uses the Python `ast` module. This module and created functionality in codeaudit does not perform type inference. 

So it cannot 100% detect whether a variable is a Connection method from the `multiprocessing` module. 

So only some common use cases are detected.
:::



## More information

* https://docs.python.org/3/library/multiprocessing.html#multiprocessing-recv-pickle-security 