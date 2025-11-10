# Random Statement 

Python Code Audit checks on use of the `random` module. Checks are done for:
* `random.seed` 
* `random.Random`
* `random.randbytes`
* `random.randint`
* `random.random`
* `random.randrange`
* `random.seed`
* `random.triangular` and
* `random.uniform`

Too often these functions are not used in the right way!

The pseudo-random generators of the module `random` should **not** be used for security purposes. 
However this is still too often neglected. 

Normal `random` use is only acceptable if the Python code is not used for security or cryptographic purposes.

## Rationale

The `random` module in Python is not safe for security or cryptographic purposes, such as generating session tokens, encryption keys, or passwords.

This is because the `random` module uses a pseudo-random number generator (PRNG) called the Mersenne Twister. This algorithm is deterministic. If an attacker can observe a sufficient amount of its output, they can completely determine its internal state (the seed) and accurately predict all future and even past values.

The `random` module is specifically designed for non-security-sensitive applications like simulations, statistical modeling, and simple games, prioritizing speed and good statistical distribution over true unpredictability.

For all security-sensitive tasks, you must use the `secrets` module, which relies on a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) provided by the operating system.


## Preventive measures

- For security or cryptographic uses, **never** use the `random` module but use the `secrets` module.

- Use `random.SystemRandom` for random numbers, but this function is not available on all systems.


## Example

```python
"""Problematic code using random module"""
import random

browser_cookie = random.randint(min_value, max_value)
```

To improve this code:
Use the  `SystemRandom` class. This class uses the system function `os.urandom()` to generate random numbers from sources provided by the operating system.

```python
from random import SystemRandom
safe_random = SystemRandom()

browser_cookie = safe_random.randint(min_value, max_value)
```


## More information

* https://docs.python.org/3/library/random.html
* https://docs.python.org/3/library/secrets.html#module-secrets
* [ CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)
* [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
* [CVE-2022-23472](https://nvd.nist.gov/vuln/detail/CVE-2022-23472)
* [PEP 506 – Adding A Secrets Module To The Standard Library](https://peps.python.org/pep-0506/)
* https://www.codiga.io/blog/python-avoid-random/
