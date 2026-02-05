import os
import builtins

b = builtins
b.exec("2+2")  # flag 1

x = 1
result = b.eval("x + 2")  # flag 2
print(result)  # 2 is already flagged?

print(eval("1+1")) # flag 3
print(eval("os.getcwd()")) # flag 4
print(eval("os.chmod('%s', 0777)" % 'test.txt')) # flag 5


# A user-defined method named "eval" should not get flagged.
class Test(object):
    def eval(self):   # flag 6 since builtins is imported!
        print("hi")
    def foo(self):
        self.eval()  # flag 7 - but a false flag , but since builtins is imported a knowen issue!

Test().eval()  # flag 8 - due to eval is in contructs list, edge case and hard to solve in a simple way (for now)


eval("os.system('rm -rf /')") # flag 9

__builtins__.eval(...)  # flag 10  due to eval statement

nasty  = __import__("builtins").eval     # flag 11  , flag due to __import__ 
