import os
import builtins

b = builtins
b.exec("2+2")  # flag 1

x = 1
result = b.eval("x + 2")  # flag 2
print(result)  

print(eval("1+1")) # flag 3
print(eval("os.getcwd()")) # flag 4
print(eval("os.chmod('%s', 0777)" % 'test.txt')) # flag 5


# A user-defined method named "eval" should not get flagged.
class Test(object):
    def eval(self):   # this will not be flagged
        print("hi")
    def foo(self):
        self.eval()  # flag 6 - but a false flag , but since builtins is imported a known issue! So #nosec

Test().eval()  # flag 7 -  due to eval is in contructs list, edge case and hard to solve in a simple way (for now), so marker nosec 


eval("os.system('rm -rf /')") # flag 8

__builtins__.eval(...)  # flag 9  due to eval statement

nasty  = __import__("builtins").eval     # flag 10 + flag 11  , flag due to __import__  and for eval!
