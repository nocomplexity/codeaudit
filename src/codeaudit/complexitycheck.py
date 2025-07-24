"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

Simple Cyclomatic Complexity check for Python source files
See the docs for in-depth and why this is a simple way , but good enough!
"""

import ast
import warnings


class ComplexityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.complexity = 1  # Start with 1 for the entry point

    def visit_If(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node):
        self.complexity += 1
        self.generic_visit(node)

    def visit_Try(self, node):
        self.complexity += 1  # For the try block
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        self.complexity += 1  # For each except clause
        self.generic_visit(node)

    def visit_With(self, node):
        self.complexity += 1  # For 'with' statements
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        # Count 'and' and 'or' operators
        # Each 'and' or 'or' introduces a new predicate
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_Match(self, node):
        # A 'match' statement itself adds to complexity
        self.complexity += 1
        self.generic_visit(node)

    def visit_MatchCase(self, node):
        # Each 'case' in a match statement is a distinct path
        # Note: The 'visit_Match' already adds 1. Each subsequent 'MatchCase'
        # For simplicity and aligning with common CC interpretations where each distinct
        # path adds 1, we'll increment for each MatchCase.
        # So count each case as a separate branch point from the 'match' entry.
        self.complexity += 1
        self.generic_visit(node)

    def visit_Assert(self, node):
        # Assert statements introduce a potential exit point (branch)
        self.complexity += 1
        self.generic_visit(node)


def calculate_complexity(code):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=SyntaxWarning)
        tree = ast.parse(code)

    visitor = ComplexityVisitor()
    visitor.visit(tree)
    return visitor.complexity


def count_static_warnings_in_file(file_path):
    """
    Parses a Python source file using AST and counts the number of warnings raised (e.g., SyntaxWarning).

    Args:
        file_path (str): Path to the Python source file.

    Returns:
        int: Number of static warnings detected during parsing.
             Returns -1 if the file cannot be read or parsed.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()

        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always")  # Capture all warnings
            ast.parse(source, filename=file_path)

        result = {"warnings": len(caught_warnings)}

        return result

    except (SyntaxError, UnicodeDecodeError, ValueError):
        return -1
