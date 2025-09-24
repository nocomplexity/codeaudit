import sys

myfriend = 
class CodeExecutor:
    """
    A class that uses the __call__ dunder method to execute
    a string of Python code. This is for educational purposes ONLY
    and is NOT recommended for real-world applications due to security risks.
    """
    def __call__(self, code_string):
        """
        The __call__ dunder method is invoked when the instance of the class
        is "called" like a function. It executes the provided code string.
        """
        print(f"Executing code: '{code_string}'")
        try:
            exec(code_string)
            print("Execution completed successfully.")
        except Exception as e:
            print(f"An error occurred during execution: {e}", file=sys.stderr)

# --- Demonstrating the usage ---

# Create an instance of the class.
executor = CodeExecutor()

print("\n--- Example 1: Executing a simple print statement ---")
executor("print('Hello from a dunder method!')")

print("\n--- Example 2: Executing a variable assignment and usage ---")
executor("a = 10\nb = 20\nprint(f'The sum is: {a + b}')")

print("\n--- Example 3: Demonstrating an error during execution ---")
executor("print(undefined_variable)")
