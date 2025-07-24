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