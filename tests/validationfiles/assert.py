
def divide(a, b):
    # Assert that the divisor 'b' is not zero.
    # If 'b' is 0, an AssertionError will be raised with the given message.
    assert b != 0, "Cannot divide by zero!"
    return a / b

# --- Example Usage ---

# This call will work correctly because b is not zero.
try:
    result1 = divide(10, 2)
    print(f"10 divided by 2 is: {result1}")
except AssertionError as e:
    print(f"Error: {e}")

print("-" * 20)

# This call will raise an AssertionError because b is zero.
try:
    result2 = divide(5, 0)
    print(f"5 divided by 0 is: {result2}")
except AssertionError as e:
    print(f"Error: {e}")

print("-" * 20)

# Another assertion example outside a function
x = 10
# Assert that x is greater than 5.
assert x > 5, "x should be greater than 5"
print(f"Assertion passed: x ({x}) is greater than 5.")
