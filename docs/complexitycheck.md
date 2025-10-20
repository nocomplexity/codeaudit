# Complexity Check

**Python Code Audit** implements a Simple Cyclomatic Complexity check, operating on the principle that secure systems are simple systems.


Complexity directly impacts security. Simple systems are:

* Maintainable: Easier to change and manage.

* Reliable: Less prone to logic errors.

* Testable: Easier to validate and test.

**Python Code Audit** tool calculates the complexity per file and provides a module-level overview to help you track this metric.



:::{tip} 
**Embrace Simplicity**

* Keep your architecture simple. 

* Prefer straightforward designs over complex, highly specific ones. 

This ensures your code is easy for others to read, manage, and change. Practice and use the [0complexity principles](https://nocomplexity.com/documents/0complexity/abstract.html)

:::



[Cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) is a software metric used to indicate the complexity of a program. It was developed by Thomas J. McCabe, Sr. in 1976. 

Calculating the cyclomatic complexity for Python source code is difficult to do accurately. Most implementations aiming for a thorough complexity score eventually become somewhat subjective or opinionated.

:::{note} 
Codeaudit takes a pragmatic and simple approach to determine and calculate the complexity of a source file.

The Complexity Score that Python Code Audit** presents gives a **good and solid** representation for the complexity of a Python source file.
:::




The complexity is determined per file, and not per function within a Python source file. I have worked with companies that calculated [function points](https://en.wikipedia.org/wiki/Function_point) for systems that needed to be created or adjusted. Truth is: Calculating exact metrics about complexity for software code projects is a lot of work, is seldom done correctly and are seldom used with nowadays devops or scrum development teams. 


:::{note} 
The complexity score of source code gives presented gives a solid indication from a security perspective.
:::

Complex code has a lot of disadvantages when it comes to managing security risks. Making corrections is difficult and errors are easily made.

## What is reported

Python Code Audit overview displays: 
* `Median_Complexity` (middle value) as score in an overview report (`codeaudit overview`) for all files of a package or a directory. 
* `Maximum_Complexity` as score in an overview report (`codeaudit overview`). This to see in one appearance if a file that **SHOULD** require a closer look from a security perspective is present.

## How is Complexity determined

Python Code Audit calculates the cyclomatic complexity of Python code using Python’s built-in `ast` (Abstract Syntax Tree) module.

## What is Cyclomatic Complexity?

From a security perspective the having an objective number for Python code complexity is crucial. Complex code has another risks profile from a security perspective. Think of cost, validations needed, expertise needed and so on. Complex code is known to be more vulnerable. 

:::{admonition} Definition
:class: note
Cyclomatic complexity is a software metric used to measure the number of independent paths through a program's source code. More paths mean more logic branches and greater potential for bugs, testing effort, or maintenance complexity.
:::

## How does Code Audit calculates the Complexity?

Every function, method, or script starts with a base complexity of 1 (i.e., one execution path with no branching).

It adds 1 for each control structure or branching point:
| **AST Node Type** | **Reason for Increasing Complexity** |
|---|---|
| If | Conditional branch (if/elif/else) |
| For, While | Loop constructs (create additional paths) |
| Try | Potential for exception handling (adds branch) |
| ExceptHandler | Each except adds a new error-handling path |
| With | Context manager entry/exit paths |
| BoolOp | and / or are logical branches |
| Match | Match statement (like switch in other langs) |
| MatchCase | Each case adds an alternative path |
| Assert | Introduces an exit point if the condition fails |


Example:
```
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
```

You can verify the complexity of any Python file the command:
```
 codeaudit filescan <filename.py>
```

Summary:
* Python Code Audit only analyzes the top-level structure. It doesn't distinguish between functions on purpose, unless the input is separated accordingly.
* Python Code Audit uses a simplified cyclomatic complexity approach to get fast inside from a security perspective. This may differ from tools, especially since implementation choices that are made for dealing with comprehensions, nested functions will be different.

