# Shelve Statement


The shelve module is backed by pickle. 

So it is insecure to load a shelf from an untrusted source. Like with pickle, loading a shelf can execute arbitrary code.

The Python `shelve` module provides a persistent, dictionary-like object. It allows you to store Python objects directly to a file, and retrieve them later, making it seem very convenient for simple data persistence. However, shelve is not secure for handling data from untrusted sources due to its underlying mechanism: it uses the pickle module for serialization and deserialization.

## Security concerns

1. Reliance on pickle
The shelve module essentially wraps the pickle module. When you store an object in a shelve database, it's pickled (serialized) and written to a file. When you retrieve an object, it's unpickled (deserialized) from the file.

2. The pickle Security Vulnerability
The core of the security issue lies with pickle. The pickle module is powerful because it can serialize and deserialize almost any Python object, including instances of classes, functions, and even code objects. To achieve this, pickle's deserialization process is designed to reconstruct Python objects by executing a sequence of bytecode instructions.


Shelve is convenient for simple, trusted data persistence (e.g., local configuration files for a single-user application where the user is the only one interacting with the file). 

It should never be used with data that originates from or can be manipulated by untrusted sources.

## More information

* https://docs.python.org/3/library/shelve.html#shelve-security