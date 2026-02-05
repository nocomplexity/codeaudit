# A user-defined method named "eval" should not get flagged.
class Test(object):
    def eval(self): #this line is not flagged!
        print("hi")
    def foo(self):
        self.eval() #this line is not flagged!

Test().eval()  #Only this line is flagged! , solvable by adding a marker. so nosec
