# Input Statement

Using the `input()` is always a security concern. Input is seldom properly handled from a defense security perspective.

When using `input` with incorrect or no validation and sanitizing the risk for remote code execution (RCE) and other serious attacks is present.

From a security perspective: The fundamental security concern lies not in use of the `input()` function itself, but in how you process use the data it receives. 

:::{hint} 
Always treat all user input as untrusted.

Validate/sanitize all input thoroughly before using it in any part of your application.
:::


## Common security concerns with the use of `input()` in Python 

  * **Injection Attacks:** If you take user input and directly embed it into:
      * **SQL queries:** SQL Injection (e.g., a user enters `' OR 1=1; --` to bypass login).
      * **Shell commands:** Command Injection (e.g., a user enters `&& rm -rf /` when you use `os.system()` or `subprocess.call()` with user-provided arguments).
      * **HTML/JavaScript for web applications:** Cross-Site Scripting (XSS) if you display unescaped user input on a web page.
  
  * **Path Traversal:** If user input is used to construct file paths, a malicious user could use `../` to access files outside of the intended directory.
  
  * **Denial of Service (DoS):** Extremely long or malformed input could consume excessive memory or CPU, leading to your program becoming unresponsive.
  
  * **Insecure Deserialization:** If you're deserializing data (e.g., using `pickle`) that was generated from user input, a malicious attacker could craft a serialized object that, when deserialized, executes arbitrary code. (This isn't directly `input()`'s fault, but it's a common pattern where `input()` might feed into it).
  
  * **Revealing Sensitive Information:** If your error handling is too verbose and displays raw error messages that include sensitive system paths or internal details based on user input, attackers can use this information for further exploitation.

## Some simple rules for handling User Input

1.  **Always Validate Input:**

      * **Whitelist Validation:** Define what constitutes valid input (e.g., only digits, specific characters, certain length) and reject anything that doesn't match. This is generally more secure than trying to blacklist bad input.
      * **Regular Expressions:** Use `re` module for complex pattern matching.
      * **Type Conversion and Error Handling:** If you expect a number, try to convert the input to `int` or `float` and handle `ValueError` gracefully.

2.  **Sanitize Input:** Remove or escape potentially dangerous characters from the input.

      * For HTML output, use libraries like `html` (built-in) or `Bleach` to escape HTML entities.
      * For database queries, use parameterized queries (prepared statements) provided by your database driver/ORM. **Never concatenate user input directly into SQL strings.**
      * For shell commands, avoid `shell=True` in `subprocess` whenever possible, and pass arguments as a list of strings. Validate and sanitize each argument.

3.  **Limit Input Size:** Restrict the maximum length of user input to prevent buffer overflows or excessive memory usage.

4.  **Avoid `eval()` and `exec()`:** As a general rule:

:::{danger} 
Never ever use `eval()` or `exec()` with user-provided strings. 
:::
 
 
 These functions are extremely dangerous as they execute arbitrary Python code.

5.  **Principle of Least Privilege:** Your application should only have the minimum permissions necessary to perform its function.

6.  **Secure Error Handling:** Don't display raw error messages to users. Log them for internal review and provide generic, user-friendly error messages instead.

