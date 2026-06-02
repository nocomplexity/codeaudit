import importlib

#dynamic modules import SHOULD be validated! Never trust, always...

user_input = input("Enter a module name to import: ")

my_module = importlib.import_module(user_input) #This what you NEVER want, but in practice programs using importlib use dynamic imports. Always understand the code before executing!

print(f"Successfully imported the {my_module.__name__} module.")