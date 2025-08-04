"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

Simple checker reporting #source code, #comments in Python files
"""

import ast
import warnings

from codeaudit.filehelpfunctions import (
    read_in_source_file,
    get_filename_from_path,
    collect_python_source_files,
)
from codeaudit.complexitycheck import (
    calculate_complexity,
    count_static_warnings_in_file,
)


def count_ast_objects(source):
    """
    Counts AST nodes and objects.
    This gives an indication of complexity and code maintainability.
    Suppresses SyntaxWarnings like invalid escape sequences.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=SyntaxWarning)
        tree = ast.parse(source)

    ast_nodes = 0
    ast_functions = 0
    ast_modules = 0
    ast_classes = 0

    for node in ast.walk(tree):
        if hasattr(node, "lineno") and isinstance(node, (ast.stmt, ast.Expr)):
            ast_nodes += 1
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ast_functions += 1
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            ast_modules += 1
        if isinstance(node, ast.ClassDef):
            ast_classes += 1

    result = {
        "AST_Nodes": ast_nodes,
        "Modules": ast_modules,
        "Functions": ast_functions,
        "Classes": ast_classes,
    }

    return result


def count_comment_lines(source):
    """Counts lines with comments and all lines inside triple-double-quoted strings"""
    comment_lines = set()
    lines = source.splitlines()
    in_triple_double = False

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        # Check for triple-double-quote boundaries
        if stripped.count('"""') == 1:
            # Start or end of a multiline string
            in_triple_double = not in_triple_double
            comment_lines.add(i)  # Count this line
        elif stripped.count('"""') >= 2:
            # Triple quotes open and close on the same line
            comment_lines.add(i)
        elif in_triple_double:
            comment_lines.add(i)
        elif line.startswith("#"):
            # Regular comment - note that inline comment are NOT counted as comment lines
            comment_lines.add(i)
    result = {"Comment_Lines": len(comment_lines)}
    return result


def count_lines_iterate(filepath):
    """
    Counts the number of lines in a file by iterating through the file object.
    This method is memory-efficient for large files.
    """
    count = 0
    try:
        with open(filepath, "r") as f:
            for line in f:
                count += 1
        return count
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return -1
    except Exception as e:
        print(f"An error occurred: {e}")
        return -1


def get_statistics(directory):
    """Get codeaudit statistics from source files in a directory"""
    files_to_check = collect_python_source_files(directory)
    total_result = []
    for python_file in files_to_check:
        result = overview_per_file(python_file)
        total_result.append(result)
    return total_result


def overview_per_file(python_file):
    """gets the overview per file."""
    result = {}
    source = read_in_source_file(python_file)
    name_of_file = get_filename_from_path(python_file)
    name_dict = {"FileName": name_of_file}
    file_location = {"FilePath": python_file}
    number_of_lines = count_lines_iterate(python_file)
    lines = {"Number_Of_Lines": number_of_lines}
    complexity_score = calculate_complexity(source)
    complexity = {"Complexity_Score": complexity_score}
    warnings_count = count_static_warnings_in_file(python_file)
    result = (
        name_dict
        | file_location
        | lines
        | count_ast_objects(source)
        | count_comment_lines(source)
        | complexity
        | warnings_count
    )  # merge the dicts
    return result


def overview_count(df):
    """returns a dataframe with simple overview of all files"""
    columns_to_sum = [
        "Number_Of_Lines",
        "AST_Nodes",
        "Modules",
        "Functions",
        "Classes",
        "Comment_Lines",
    ]
    df_totals = df[columns_to_sum].sum().to_frame().T  # .T to make it a single row
    total_number_of_files = df.shape[0]
    df_totals.insert(
        0, "Number_Of_Files", total_number_of_files
    )  # insert new column as first colum
    median_complexity = round(df["Complexity_Score"].mean(), 1)
    df_totals["Median_Complexity"] = median_complexity
    maximum_complexity = df["Complexity_Score"].max()
    df_totals["Maximum_Complexity"] = maximum_complexity
    return df_totals
