"""Input itself is not unsafe, BUT seldom sanitizing and validation is done simple and correct.
Mind 100% sanitizing is often impossible - so there is always a risk.
"""

def greet_user():
    name = input("What is your name? ")
    print(f"Hello, {name}!")
