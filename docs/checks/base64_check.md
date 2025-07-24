# Base64 Statements

Codeaudit checks on use of:
*  Base64 Encoding / Decoding

The `base64` module requires specific security considerations.

It’s recommended to review the security considerations for any code deployed to production using `base64` encoding.

Security considerations section from RFC 4648 (section 12):

```text
Security Considerations

   When base encoding and decoding is implemented, care should be taken
   not to introduce vulnerabilities to buffer overflow attacks, or other
   attacks on the implementation.  A decoder should not break on invalid
   input including, e.g., embedded NUL characters (ASCII 0).

   If non-alphabet characters are ignored, instead of causing rejection
   of the entire encoding (as recommended), a covert channel that can be
   used to "leak" information is made possible.  The ignored characters
   could also be used for other nefarious purposes, such as to avoid a
   string equality comparison or to trigger implementation bugs.  The
   implications of ignoring non-alphabet characters should be understood
   in applications that do not follow the recommended practice.
   Similarly, when the base 16 and base 32 alphabets are handled case
   insensitively, alteration of case can be used to leak information or
   make string equality comparisons fail.

   When padding is used, there are some non-significant bits that
   warrant security concerns, as they may be abused to leak information
   or used to bypass string equality comparisons or to trigger
   implementation problems.

   Base encoding visually hides otherwise easily recognized information,
   such as passwords, but does not provide any computational
   confidentiality.  This has been known to cause security incidents
   when, e.g., a user reports details of a network protocol exchange
   (perhaps to illustrate some other problem) and accidentally reveals
   the password because she is unaware that the base encoding does not
   protect the password.

   Base encoding adds no entropy to the plaintext, but it does increase
   the amount of plaintext available and provide a signature for
   cryptanalysis in the form of a characteristic probability
   distribution.
```

## More information

* https://docs.python.org/3/library/base64.html#base64-security
* https://datatracker.ietf.org/doc/html/rfc4648.html#page-14 