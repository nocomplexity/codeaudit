# XML security

xmlrpc is vulnerable to the “decompression bomb” attack.

An attacker can abuse XML features to carry out denial of service attacks, access local files, generate network connections to other machines, or circumvent firewalls.

Parsing XML **SHOULD** always be done when various measurements against malformed xml are implemented. Creating and using the Python `xml` module has great benefits, but mind to take security concerns very seriously!



## More info

* https://docs.python.org/3/library/xml.html#xml-security 