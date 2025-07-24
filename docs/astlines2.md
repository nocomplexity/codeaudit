# AST Lines to count - part 2


The distinction between `if hasattr(node, 'lineno')` and `if hasattr(node, 'lineno') and isinstance(node, (ast.stmt, ast.Expr))` is significant because it determines *what kind of code elements* you're counting as "lines."


1.  **Not all nodes with `lineno` are "executable" lines of code.**
    While many AST nodes have `lineno` (line number) and `col_offset` attributes to pinpoint their location in the source file, not all of them represent a distinct "line of code" that contributes to the logic or execution flow in the way you usually want to count.

    Consider these examples:
    * **`ast.Load`, `ast.Store`, `ast.Del` (Context nodes):** These are context objects (`Load` for reading a variable, `Store` for assigning to it, `Del` for deleting it). They have `lineno`, but they are usually children of other nodes (like `ast.Name` or `ast.Attribute`) that already represent the "line" where the operation occurs. Counting them separately would inflate your line count.
    * **`ast.arguments`, `ast.arg` (Function argument definitions):** These nodes describe function arguments. While they appear on specific lines, they are part of a `FunctionDef` node, and the `FunctionDef` itself typically covers the line where the function signature is defined. Counting `arg` nodes as separate "lines" would be misleading if you're trying to count functional code lines.
    * **`ast.Constant` (Simple literals):** A simple integer like `1` or a string `"hello"` might be its own `ast.Constant` node with a `lineno`. If it's part of a larger expression, you usually don't want to count it as a separate line. For example, `x = 1 + 2` is one line, not three, even though `1` and `2` might be `Constant` nodes.

2.  **Focusing on `ast.stmt` and `ast.Expr` captures the "action" lines.**
    * **`ast.stmt` (Statements):** This is the base class for all statement nodes. Statements are the "actions" in your code: assignments (`Assign`), function definitions (`FunctionDef`), `if` statements (`If`), `for` loops (`For`), `return` statements (`Return`), `import` statements (`Import`), etc. Each of these generally corresponds to a distinct logical line of code.
    * **`ast.Expr` (Expression Statements):** This is a special type of statement that wraps an expression when that expression stands alone as a statement (e.g., a function call like `print("hello")` or a simple literal that isn't assigned, though the latter is rare in practical code). For example, `f(x)` by itself on a line is an `ast.Expr` node containing an `ast.Call` expression. While the actual call is an expression, its appearance as a standalone line makes it a "code line."

    By filtering for `ast.stmt` and `ast.Expr`, you are specifically targeting the nodes that represent the primary structural and executable components of your Python code, giving you a more accurate count of "logical lines."

**In summary:**

* `if hasattr(node, 'lineno')`: This is too broad. It will include many granular nodes that are children or components of other "main" nodes, leading to an inflated and less meaningful count of "lines."
* `if hasattr(node, 'lineno') and isinstance(node, (ast.stmt, ast.Expr))`: This is more precise. It focuses on the top-level statements and expression-statements, which typically align with what a human would consider a line of executable code.

This refined filtering helps you count lines more meaningfully, aligning with common definitions of "lines of code" that exclude comments, whitespace, and very granular sub-nodes that don't represent a distinct executable action.