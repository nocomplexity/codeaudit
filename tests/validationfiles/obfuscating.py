#Example of obfuscating dangerous constructs that are hard to find!

import builtins
b = builtins
b.exec("2+2")

result = b.eval("x + 2")
print(result)  # 3

x = 1
eval('x+1')

#now test for obfuscating with exec 
variables = {}
# Execute the code and store the result in the 'variables' dictionary - The exec return value is None, so we store the result
b.exec('result = x + 1', {'x': x}, variables)
# The result is now accessible in the 'variables' dictionary
print(variables['result'])


ℯ𝓍ℯ𝒸("print(2 + 2)")  #Confusable homoglyphs - proper AST parsing will be detect this as a regular exec call. When regexes are used (as done in a lot of SAST checkers), the input must be normalized first. Python Code Audit detects this!


c = builtins
result = c.input('number?')  #Input should not be obfuscated. Code Audit will detect this!
print(result)

number = input("number to find a security issue?")

d = builtins
code_obj = d.compile('x = 5*5\nprint(x)', '<string>', 'exec')
result = d.exec(code_obj)  #Input should not be obfuscated. Code Audit will detect this!
print(result)

e = builtins
__import__("builtins").exec("2+2") # This is by default detected by Code Audit
__import__("builtins").e.exec("2+2") # This is by default detected by Code Audit


result = __import__("builtins").eval("2+2")  #The __import__ should NOT be used in normal Python programs, see doc https://docs.python.org/3/library/functions.html#import__
print(result)


result = getattr(__import__("built"+"ins"),"ev"+"al")("2+2") #Is detected since __import is used"
print(result)

result = getattr(__import__("built"+"ins"),"ex"+"ec")("2+2")
print(result)

import importlib
#dynamic modules import SHOULD be validated! Never trust, always...
user_input = input("Enter a module name to import: ")
my_module = importlib.import_module(user_input) #This what you NEVER want, but in practice programs using importlib use dynamic imports. Always understand the code before executing!
print(f"Successfully imported the {my_module.__name__} module.")