# AST Lines for code complexity

A simple way to count the number of lines of a file can be done with various unix commands. 
Simple is to use the `wc` command. However counting lines is different from counting AST lines in a Python program.

AST lines are needed to give a more precise indication of the complexity of a Python program.


To explain the difference between an **AST line** (as counted by the provided `count_ast_lines` function) and a **line counted by the Unix `wc` command**, let’s break it down:

1. **Lines Counted by Unix `wc -l`**
- The Unix command `wc -l filename` counts the **physical lines** in a file.
- A "line" is defined as any sequence of characters terminated by a newline character (`\n`).
- This includes:
  - Code lines (e.g., `def foo():`).
  - Blank lines (e.g., just `\n`).
  - Comment lines (e.g., `# This is a comment`).
  - Multi-line strings or statements split across lines.
- **Example**:
  ```python
  # Comment
  def foo():
      pass

  x = 1  # Another comment
  ```
  Running `wc -l` on this file yields **5 lines** because there are five newline characters (one for each line, including the blank line).

2. **AST Lines (as counted by `count_ast_lines`)**
- The `count_ast_lines` function uses Python’s `ast` module to parse the source code into an **Abstract Syntax Tree (AST)** and counts **unique lines that contain AST nodes with a `lineno` attribute**.
- An AST represents the syntactic structure of the code, ignoring comments, blank lines, and certain non-executable elements.
- The function:
  - Parses the source code into an AST using `ast.parse`.
  - Uses a `LineCollector` class (inheriting from `ast.NodeVisitor`) to traverse the AST.
  - Collects unique line numbers (`lineno`) from nodes that have a `lineno` attribute (e.g., statements, expressions).
  - Returns the count of unique lines with executable code.
- **What counts as an AST line?**
  - Lines containing executable Python statements or expressions (e.g., function definitions, assignments, loops, etc.).
  - Lines that are part of multi-line statements (e.g., a multi-line function call or dictionary).
  - The first line of a multi-line string or compound statement (e.g., `def`, `if`) typically gets the `lineno` in the AST.
- **What is excluded?**
  - Blank lines.
  - Comment lines (e.g., `# Comment`).
  - Lines that are purely continuation lines of multi-line strings or statements (only the first line with the node is counted).
- **Example**:
  ```python
  # Comment
  def foo():
      pass

  x = 1  # Another comment
  ```
  Using `count_ast_lines` on this code:
  - The AST nodes with `lineno` are:
    - `def foo():` (line 2, FunctionDef node).
    - `pass` (line 3, Pass node).
    - `x = 1` (line 5, Assign node).
  - The `set` of line numbers is `{2, 3, 5}`, so `count_ast_lines` returns **3**.

3. **Key Differences**
| Aspect                     | `wc -l`                              | `count_ast_lines` (AST Lines)         |
|----------------------------|--------------------------------------|---------------------------------------|
| **Definition**             | Counts physical lines (newline-terminated). | Counts unique lines with AST nodes.   |
| **Includes Comments**      | Yes                                  | No                                    |
| **Includes Blank Lines**   | Yes                                  | No                                    |
| **Multi-line Statements**  | Counts every physical line           | Counts only the line with the node (usually the first). |
| **Purpose**                | General file line count              | Measures executable code lines        |
| **Example Output**         | 5 (for above example)                | 3 (for above example)                 |

4. **Additional Example for Clarity**

Consider this code:
```python
# This is a comment
def example():
    """
    Multi-line docstring
    spanning multiple lines
    """
    x = {
        'a': 1,
        'b': 2
    }
    return x

# Another comment
```
- **Unix `wc -l`**:
  - Counts all 12 physical lines (comment, blank, code, docstring lines, etc.).
  - Output: `12`.
- **count_ast_lines**:
  - AST nodes with `lineno`:
    - `def example():` (line 2, FunctionDef node).
    - `"""Multi-line docstring..."""` (line 3, Expr node for docstring).
    - `x = {...}` (line 7, Assign node).
    - `return x` (line 11, Return node).
  - Unique line numbers: `{2, 3, 7, 11}`.
  - Output: `4`.

5. **Why the Difference Matters**
- `wc -l` is useful for getting a raw count of lines in a file, often used for file statistics or quick checks.
- `count_ast_lines` is more relevant for analyzing **executable code complexity** or **code coverage**, as it focuses on lines that represent actual Python syntax nodes, ignoring non-executable content like comments or blank lines.

Let me know if you need further examples or clarification!