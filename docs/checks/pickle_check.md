# Pickle Statement

Codeaudit checks on the use of the `pickle` statement. 

:::{danger} 
Unpickling will import any class or function that it finds in the pickle data. This is a severe security concern as it permits the unpickler to import and invoke arbitrary code. 

**Never use `pickle.load()` or `pickle.loads()` on data received from an untrusted or unauthenticated source.**

:::

When you use `pickle.load()` to deserialize a byte stream, the `pickle` module essentially reconstructs Python objects from that stream. A malicious attacker can craft a pickled payload that, when deserialized, can:


The security concern with the `pickle` module in Python revolves around **deserialization of untrusted data**.

The main call that poses a security risk is:

* **`pickle.load()`** (and its variations like `pickle.loads()` for bytes)

`pickle.load()` is dangerous with untrusted data:


1.  **Execute arbitrary code:** The `pickle` protocol can be manipulated to cause the deserializer to import arbitrary modules and call arbitrary functions with arbitrary arguments. This means an attacker can execute system commands, delete files, or do anything else the Python process running `pickle.load()` has permissions to do. This is often referred to as a "deserialization vulnerability" or "arbitrary code execution."

2.  **Cause Denial of Service (DoS):** An attacker could create a pickled object that, when deserialized, consumes excessive memory or CPU resources, leading to your application crashing or becoming unresponsive.


## More information

* https://docs.python.org/3/library/pickle.html#pickle-restrict