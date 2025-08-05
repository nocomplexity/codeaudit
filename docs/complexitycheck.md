# Codeaudit complexity Check

The Python `codeaudit` tool implements a Simple Cyclomatic complexity check.


[Cyclomatic complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity) is a software metric used to indicate the complexity of a program. It was developed by Thomas J. McCabe, Sr. in 1976. 

Calculating the Cyclomatic complexity for Python sources is complex to do right. And seldom needed! Most implementations for calculating a very thorough Cyclomatic Complexity end up being opinionated sooner or later.

:::{note} 
Codeaudit takes a pragmatic and simple approach to determine and calculate the complexity of a source file.

**BUT:**
The Complexity Score that Codeaudit presents gives a **good and solid** representation for the complexity of a Python source file.
:::


But I known the complexity score is not an exact exhaustive cyclomatic complexity measurement.


The complexity is determined per file, and not per function within a Python source file. I have worked long ago with companies that calculated [function points](https://en.wikipedia.org/wiki/Function_point) for software that needed to be created or adjusted. Truth is: Calculating exact metrics about complexity for software code projects is a lot of work, is seldom done correctly and are seldom used with nowadays devops or scrum development teams. 


:::{tip} 
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

