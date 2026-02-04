import os
import builtins

b = builtins
b.exec("2+2")

x = 1
result = b.eval("x + 2")
print(result)  # 3

print(eval("1+1"))
print(eval("os.getcwd()"))
print(eval("os.chmod('%s', 0777)" % 'test.txt'))


# A user-defined method named "eval" should not get flagged.
class Test(object):
    def eval(self):
        print("hi")
    def foo(self):
        self.eval()

Test().eval()
