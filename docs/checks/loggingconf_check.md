# Logging Statement 

Codeaudit checks on the Logging Configuration used.

Using Python's logging module can be a security risk if sensitive information is logged without proper sanitization or access control. Attackers could exploit this to gain insights into system internals, user data, or application logic, aiding further attacks like privilege escalation or data exfiltration.

The logging configuration functionality tries to offer convenience, and in part this is done by offering the ability to convert text in configuration files into Python objects used in logging configuration - for example, as described in User-defined objects. 

However, these same mechanisms (importing callables from user-defined modules and calling them with parameters from the configuration) could be used to invoke any code you like, and for this reason you should treat configuration files from untrusted sources with extreme caution and satisfy yourself that nothing bad can happen if you load them, before actually loading them.

:::{attention} 
Creating pipes and importing dicts for configuration can be a security nightmare.
:::


Portions of the configuration are passed through `eval()`, use of this function may open its users to a security risk. While the function only binds to a socket on localhost, and so does not accept connections from remote machines, there are scenarios where untrusted code could be run under the account of the process which calls listen(). Specifically, if the process calling listen() runs on a multi-user machine where users cannot trust each other, then a malicious user could arrange to run essentially arbitrary code in a victim user’s process, simply by connecting to the victim’s listen() socket and sending a configuration which runs whatever code the attacker wants to have executed in the victim’s process. This is especially easy to do if the default port is used, but not hard even if a different port is used. To avoid the risk of this happening, use the verify argument to listen() to prevent unrecognised configurations from being applied.


Python `codeaudit` checks on use of:
* `logging.config`


## More information
* [Security considerations - PSF Python manual](https://docs.python.org/3/library/logging.config.html#security-considerations)