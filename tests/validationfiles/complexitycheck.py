"""complexity of code below should count to 4
Complexity breakdown:
1 (base)


+1 (if)


+1 (and) operator inside if


+1 (elif) — counted as another If node in AST
 = 4

"""
def test(x):
    if x > 0 and x < 10:
        print("Single digit positive")
    elif x >= 10:
        print("Two digits or more")
    else:
        print("Non-positive")
