# Binding Statement

Purpose of this validation is to detect code construct where binding to all interfaces is applied.

The Python construct `s.bind()` is dangerous from a security perspective.

It opens network sockets and makes your application vulnerable. Additional measurements are often required. So not only within the Python code. This is seldom enough.

When `s.bind` constuct is detected this requires a further inspection to determine what the risks are. This inspection can only be done in full context, so in context of the environment where the code will be executed. 

## Additional explanation 

Within Python Binding sockets on all interfaces can be done on several ways. E.g.:
```python
import socket

addr = ("", 8080)  # all interfaces, port 8080
if socket.has_dualstack_ipv6():
    s = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True)
else:
    s = socket.create_server(addr)
```
([reference - Python documentation](https://docs.python.org/3/library/socket.html#socket.AF_INET6))

:::{caution} 
Port bindings **SHOULD** never be hardcoded. But if used dynamically assigned based on ports that are not yet in use. 

When multiple sockets are allowed to bind to the same port, other services on that port may be stolen or spoofed.

So prevent an another application to bind to the specific address on unprivileged port, and steal its UDP packets/TCP connection.

Minimal required is a strong authorization mechanism and preferred is a 'zero-trust' network policy. 

**Make sure measurements are taken** when communication using raw sockets in Python.

:::

Some measurements (besides changing the code!) are:

1.  **Firewall Configuration:** Configure a to explicitly allow incoming connections *only from trusted sources* or specific IP ranges. Block all other incoming connections to that port.

2.  **Application Security:**
    * **Authentication and Authorization:** Implement strong authentication and authorization mechanisms for your application. Don't leave it open for anyone to connect.
    * **Input Validation:** Sanitize and validate all user inputs to prevent common vulnerabilities like SQL injection, cross-site scripting (XSS), and command injection.
    * **Least Privilege:** Ensure the application runs with the minimum necessary privileges.
    * **Error Handling:** Implement robust error handling that doesn't expose sensitive system information.
    * **Logging and Monitoring:** Log access attempts and suspicious activities. Monitor these logs for anomalies.

4.  **Zero-Trust and Network Segmentation:** For critical services, consider placing them in separate network segments to limit lateral movement if one part of your network is compromised.



## More Information
 * https://docs.python.org/3/library/socket.html