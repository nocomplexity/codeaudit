# Insecure hashing

Codeaudit checks the use of insecure hashing functions. 

The Python library `hashlib` is great. But using insecure hashing algorithms is still possible and should be avoided!

So CodeAudit performs a check on usage of the insecure hash algorithms:
* md5
* sha1

[From Python 3.9 and higher](https://docs.python.org/3/library/hashlib.html#hashlib-usedforsecurity):
* All hashlib constructors take a keyword-only argument `usedforsecurity` with default value True. A false value allows the use of insecure and blocked hashing algorithms in restricted environments. False indicates that the hashing algorithm is not used in a security context, e.g. as a non-cryptographic one-way compression function.

:::{danger} 
Unless there is a very good reason to still use `md5` or `sha1`, which is almost impossible, you should demand a fix. Or if you are the developer of the code make the fix.
:::

## More information

* https://docs.python.org/3/library/hashlib.html#hashlib-usedforsecurity
* [Attacks on cryptographic hash algorithms](https://en.wikipedia.org/wiki/Cryptographic_hash_function#Attacks_on_cryptographic_hash_algorithms) 
* https://cwe.mitre.org/data/definitions/327.html
* [OWASP Top 10:2021 ](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
* [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
* [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)