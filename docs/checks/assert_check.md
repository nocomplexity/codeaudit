# Assert Statement

The Python `assert` statement itself is not insecure, but its *misuse* can lead to security vulnerabilities. 

:::{danger} 
Using `assert` can be problematic from a security perspective!
:::


## Rationale

1. Assertions are primarily for debugging and development, **NOT** for production validation or error handling.

* **They can be disabled:** When Python is run in optimized mode (with the `python -O` or `python -OO` flags, or by setting the `PYTHONOPTIMIZE` environment variable), `assert` statements are completely ignored. 

When using `python -O` or `python -OO` the Python interpreter removes all assert statements from the bytecode.

This means any crucial checks you rely on for security or data integrity will simply vanish, leaving your application vulnerable.

* **Not for user input validation:** So never use `assert` to validate user input or external data. If assertions are disabled in production, malicious or malformed input will bypass your checks, potentially leading to crashes, data corruption, or even arbitrary code execution. Use `if/else` statements with proper exception handling (e.g., `ValueError`, `TypeError`) for this.

* **Not for graceful error handling:** Assertions are designed to signal "this should never happen, it's a bug." They raise an `AssertionError` which typically halts the program. In a production environment, you usually want to handle anticipated errors gracefully, log them, and potentially recover or inform the user, rather than crashing the application.

2. Some side effects within `assert` statements can be dangerous.

* If an `assert` statement contains code with side effects (e.g., modifying a variable, calling a function that performs an action), those side effects will also be skipped when assertions are disabled. This can lead to unexpected behavior and security gaps.

3. Use assert for testing code and during development only

* `assert` is good to use for `pytest` or other development constructs. 

* `Assert` helps to find mistakes during development. But it is not a security fence to protect against external threats or a robust mechanism for handling runtime issues in a live system. For production code, especially when dealing with external inputs or critical business logic, rely on explicit `if/else` checks and robust exception handling.

 * `Assert` statements should in general only be used for testing and debugging purposes. 
 `assert` statements **SHOULD** be removed when not running in debug mode (i.e. when invoking the Python command with the -O or -OO options).


## Example

The following Python example shows how trusting on `assert` can lead to another behaviour.


```python
"""Example of Python script using the assert statement - which can lead to security issues!"""

def divide_numbers(x,y):
    """
    Divides two numbers.
    Uses an assert statement to ensure the denominator is not zero.
    """
    # Assert that the denominator is not zero.
    # If denominator is 0, an AssertionError will be raised with the given message.
    assert y != 2, "Error: diving is crying!"
    return x / y

print("--- Demonstrating danger of assertions ---")
result = divide_numbers(10, 3)
print(f"Dividing result : {result}")

result2 = 'Error- Dividing is crying!' # A default value to show
try:
    # If run with 'python -O', the 'assert y != 0' line above will be removed.
    # In that scenario, this call will directly raise a ZeroDivisionError,
    # as the assert check won't be present.
    result2 = divide_numbers(10, 2)
except AssertionError as e:
    # This block will be executed if assert is active (without -O)
    print(f"Caught an AssertionError: {e}")
    print('Never divide! Take it all or divide in more parts.')   


print(f"Dividing result - Result should be error, not 5! - : {result2}")

```

Run this program with:
```
python assert_example.py
```
And after that another time with:
```
python -O assert_example.py
```
And notice the different outcome.


So this examples shows that if you rely on `assert` to prevent an `AssertionError` (or any other critical condition), that check will simply disappear in an optimized environment!

Instead of catching an `AssertionError`, a program will run differently when `python -O` is used. And this can and will have consequences for the functional working of a program. But worse it can have severe security consequences. E.g. if asserts are used to validate user input to prevent sql injections e.g. 

For robust validation and error handling in production code, always use standard if statements combined with raising appropriate exceptions (like `ValueError`, `TypeError`, or custom exceptions) rather than assert.



## More information

* [The assert statement - Python Documentation](https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement)
* [The dangers of assert in Python](https://snyk.io/blog/the-dangers-of-assert-in-python/)
* [Feature: Python assert should be consider harmful](https://community.sonarsource.com/t/feature-python-assert-should-be-consider-harmful/38501) But note that Sonar did not implement this check.
