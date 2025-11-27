# Built-in Functions

Some Python built-in functions can cause severe risks. 

The Python built-in functions:
* `eval`
* `exec` and
* `compile`
Should always be reviewed within the full context. By default use of this function is a **red** alert from a security perspective.

Python Code Audit checks also on Builtin that are 'hidden':

* Confusable homoglyphs like: `ℯ𝓍ℯ𝒸("print(2 + 2)")` Statements are detected.

* Obfuscating usage of builtins module calls of `eval`, `exec` and `compile` like:
```python
import builtins
b = builtins
b.exec("2+2")
```
Or
```python
code_obj = d.compile('x = 5*5\nprint(x)', '<string>', 'exec')
result = d.exec(code_obj)  #Input should not be obfuscated. Code Audit will detect this!
```

## Why check on `eval`

:::{admonition} Security risk
:class: danger
`eval()` can execute arbitrary Python code. 

If the input is user-controlled or from an untrusted source, this can be exploited.
:::

So calling `eval` with user-supplied input may lead to security vulnerabilities.

The `eval` function can also be used to execute arbitrary code objects (such as those created by `compile()`). 

Normal Python programs should not need to use this built-in function.


The primary security concern with Python’s built-in `eval()` is its potential to enable **Remote Code Execution (RCE)**. Passing untrusted input to `eval()` is effectively the same as letting an attacker run arbitrary Python code on your system.

Key Security Risks when using `eval`:

1. **Arbitrary Code Execution (RCE)**

   * `eval()` runs any Python code in the string it receives. If an attacker controls that string, they can execute malicious commands—stealing data, reading files, or invoking dangerous modules like `os` or `subprocess`.

2. **Broken Sandboxing**

   * Attempts to make `eval()` “safe” by restricting variables or the execution environment are unreliable. Attackers often find creative ways to escape these sandboxes and access sensitive data, functions, or the file system.

3. **Denial of Service (DoS)**

   * Even without stealing data, attackers can craft inputs that trigger infinite loops, deep recursion, or memory exhaustion. This can crash the interpreter or take down an entire service.



:::{warning} 
This function is capable of executing any Python code given to it. Passing unvalidated external input (such as user input, or file contents , or API retrieved content) is a major security flaw that enables arbitrary code execution. 

**Never ever not use this function on data from untrusted sources.**
:::

## Why Check on `exec`

:::{danger} 
The use of the exec() function in Python should never be permitted from a security perspective. 

It can executes arbitrary code. Or be called with untrusted input. This is a direct path to a severe security compromise.
:::

This function executes arbitrary code. Calling it with user-supplied input may lead to security vulnerabilities.


Using `exec` in Python should never be tolerated from a security perspective. Key risks are:

1. **Arbitrary Code Execution:** Executes any string as Python code; untrusted input can lead to full system compromise.
2. **Sandboxing Fails:** Attempts to restrict execution are often bypassed.
3. **Denial of Service:** Malicious code can cause infinite loops or memory exhaustion.
4. **Injection Risk:** Dynamic code with user input creates exploitable injection points.
5. **Hidden Side Effects:** Alters variables or global state unpredictably, introducing security and reliability issues.





## Why check on `compile`

As a general rule:
* Never trust Python code that uses `compile`. Verify and understand all risks before running such a program.

Security reasons to avoid Python’s built-in `compile()`:

1. **Arbitrary Code Execution**

   * `compile()` takes raw strings and turns them into executable Python code objects. If user input is passed to it (directly or indirectly), an attacker can execute arbitrary Python code on your system.

2. **Bypassing Sandboxing or Input Validation**

   * Using `compile()` can allow malicious input to bypass normal validation layers. Even if you sanitise strings for SQL or HTML, a crafted payload compiled into Python bytecode can escape restrictions.

3. **Denial of Service (DoS) via Resource Exhaustion**

   * Large or deeply nested input passed to `compile()` can consume huge amounts of CPU, memory, or recursion depth, potentially crashing the interpreter (e.g., from complex expressions or nested structures).

4. **Exposure of Sensitive Data**

   * Once arbitrary code is compiled and run, it can access system resources, environment variables, secrets in memory, or files on disk—leading to credential leaks or other security breaches.



:::{warning} 
Compiling very large or deeply nested strings into an AST object can crash the Python interpreter. This happens because Python’s AST compiler has stack depth limitations, which may be exceeded by sufficiently complex input.
:::

:::{warning} 
Also the construct `ast.literal_eval` is not safe!
Using this construct can still crash the Python interpreter due to stack depth limitations in Python’s AST compiler.

[Reference](https://docs.python.org/3/library/ast.html#ast.literal_eval)
:::

## Preventive measures

* Avoid using `eval`,`exec` and `compile`: Find a secure way by design, so rethink your design again from a security perspective. There is always a better and safer solution.

* Use a battle-tested safe expression evaluator.

* Rethink the architecture to eliminate exec(), which introduces unnecessary risk.

* For in-browser sandboxing, use Pyodide (e.g., via JupyterLite)(https://jupyterlite.readthedocs.io/en/latest/ ).

* Call Functions or Methods by Name (String Input)
If a function needs to be called based on a string name (e.g., from user input), store the functions in a dictionary and look them up by key. Avoid:
```python
func_name = input("Enter function to run: ")
exec(f"{func_name}()")
```

Recommended Alternative (Dictionary of Functions):

```python
def greet():
    print("Hello!")

def quit_app():
    import sys
    sys.exit()

available_functions = {
    "greet": greet,
    "quit": quit_app
}

func_name = input("Enter function to run (greet or quit): ")
if func_name in available_functions:
    available_functions[func_name]()
else:
    print("Unknown function")
```

* For evaluating simple, safe expressions, use ast.literal_eval() which safely evaluates basic Python literals without allowing full code execution.
Avoid:
```
exec("import os; os.system('your_command')")
```
Recommended Alternative (`ast.literal_eval`):
```python
import ast
user_input = "(2 + 3) * 5"
try:
    result = ast.literal_eval(user_input)
    print(result)
except (ValueError, SyntaxError):
    print("Invalid input")
```




## More information

* [CWE-94: Improper Control of Generation of Code ('Code Injection')](https://cwe.mitre.org/data/definitions/94.html)
* https://docs.python.org/3/library/functions.html#eval 

* https://docs.python.org/3/library/functions.html#exec

* https://docs.python.org/3/library/functions.html#compile

* [CVE-2025-3248 Detail](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)

* [CVE-2025-3248 – Unauthenticated Remote Code Execution in Langflow via Insecure Python exec Usage](https://www.offsec.com/blog/cve-2025-3248/)