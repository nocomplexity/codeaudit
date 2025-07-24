# HTTP Server Use

Use of the built-in Python `http.server` is an easy way to get a webserver up and running.
However the use of this construct **SHOULD** never leave your development environment. 

Distributing Python programs and running this construct in a secure container is never recommended. Using insecure network paths and modules is a bad idea. Developing and testing can also be regarded as **production**, so just make use of `Apache` or `NGINX` e.g.

More information:
* https://docs.python.org/3/library/http.server.html#module-http.server
* https://docs.python.org/3/library/http.server.html#http-server-security