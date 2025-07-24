# Insecure functions

Codeaudit checks the use of insecure functions. 

The Python library `hashlib` is great. But using insecure hashing algorithms is still possible and should be avoided!

So a check is done on usage of insecure hash algorithms:
* md5
* sha1

[From Python 3.9 and higher](https://docs.python.org/3/library/hashlib.html#hashlib-usedforsecurity):
* All hashlib constructors take a keyword-only argument usedforsecurity with default value True. A false value allows the use of insecure and blocked hashing algorithms in restricted environments. False indicates that the hashing algorithm is not used in a security context, e.g. as a non-cryptographic one-way compression function.

## More information

* https://docs.python.org/3/library/hashlib.html#hashlib-usedforsecurity
* [Attacks on cryptographic hash algorithms](https://en.wikipedia.org/wiki/Cryptographic_hash_function#Attacks_on_cryptographic_hash_algorithms) 
* https://cwe.mitre.org/data/definitions/327.html
