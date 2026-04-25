# FTP Statement


Use of `ftplib.FTP` from the `ftplib` is insecure and should be avoided in modern applications.

The use of `ftplib.FTP` is  insecure and should be avoided in modern application development. This class implements the legacy File Transfer Protocol (FTP), which lacks native encryption for both authentication and data transmission.



:::{danger} 
Never ever allow or use `ftplib.FTP`.

Even within isolated or private networks, the risk of credential theft and data interception is unacceptably high. Always implement protocols that secure data transfers by default.


:::

## Security concerns


Using ftplib.FTP introduces several risks:

- **Cleartext Credentials:** Usernames and passwords are transmitted in plain text, making them trivial to intercept via network sniffing.
- **Unencrypted Data Transfer:** File contents and directory structures are sent without encryption, allowing attackers to read or modify data in transit.

- **Man-in-the-Middle (MITM) Attacks:** Because the protocol lacks cryptographic integrity checks, traffic can be captured or altered by an attacker positioned between the client and server.

- Usernames and passwords are transmitted without encryption, making them vulnerable to interception.

- Files and directory listings can be read or modified by an attacker during transit.
- Susceptibility to interception attacks
- FTP traffic can be captured or altered via man-in-the-middle (MITM) attacks.
- False sense of security through aliasing

- Deceptive Aliasing: Renaming the class (e.g., `from ftplib import FTP as SecureFTP`) provides no technical security and **is dangerously misleading.** .So **misleading op purpose**!
- Network compatibility issues
- FTP’s use of multiple ports can lead to firewall and NAT traversal problems, increasing operational risk.


## Preventive measures

To mitigate these risks:

* Avoid `ftplib.FTP` entirely
* Do not use plain `FTP` in production or for sensitive data.
* Use secure alternatives
    - Prefer `SFTP` (SSH File Transfer Protocol) via `paramiko`
    - Alternatively, use `FTPS` with `ftplib.FTP_TLS` where `SFTP` is not available
* Enforce encrypted communication
* Ensure all authentication and file transfers occur over encrypted channels.
* Validate third-party integrations
* Confirm that external services support secure protocols before integration.
* Apply secure credential handling
* Store and manage credentials using secure mechanisms (e.g. environment variables or secrets managers)

## More information

* [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
* https://docs.python.org/3/library/ftplib.html 