"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 

Helper functions for files
"""

import os
import sys
from pathlib import Path
import ast
import warnings

def read_in_source_file(file_path):
    # Ensure file_path is a Path object
    file_path = Path(file_path)

    if file_path.is_dir():
        print(
            "Error: The given path is a directory.\nUse 'codeaudit directoryscan' to audit all Python files in a directory.\nThe 'codeaudit modulescan' command works per file only, not on a directory.\nUse codeaudit -h for help"
        )
        sys.exit(1)

    if file_path.suffix != ".py":
        print("Error: The given file is not a Python (.py) file.")
        sys.exit(1)

    try:
        with file_path.open("r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        print(f"Failed to read file: {e}")
        sys.exit(1)


def collect_python_source_files(directory):
    """
    Collects all Python source files (.py) from a directory, including subdirectories,
    while skipping directories that are hidden (start with '.') or underscore-prefixed,
    or are in a predefined exclusion list.

    Args:
        directory (str): The path to the directory to search.

    Returns:
        list: A list of absolute paths to valid Python source files.
    """
    EXCLUDE_DIRS = {"docs", "docker", "dist", "tests"}    
    python_files = []

    for root, dirs, files in os.walk(directory):
        # Filter out unwanted directories
        dirs[:] = [
            d for d in dirs
            if not (
                d.startswith(".") or d.startswith("_") or d in EXCLUDE_DIRS
            )
        ]

        for file in files:
            if file.endswith(".py") and not file.startswith("."):
                full_path = os.path.join(root, file)
                if os.path.isfile(full_path):
                    python_files.append(os.path.abspath(full_path))
    #check if the file can be parsed using the AST
    final_file_list = []
    for python_file in python_files:
        if is_ast_parseable(python_file):
            final_file_list.append(python_file)
        else:
            print(f'Error: {python_file} will be skipped due to syntax error while parsing into AST.')
    return final_file_list


def get_filename_from_path(file_path):
    """
    Extracts the file name (including extension) from a full path string.

    Args:
        file_path (str): The full path to the file.

    Returns:
        str: The file name.
    """
    return os.path.basename(file_path)


def is_ast_parseable(file_path):
    """
    Checks whether a Python file can be parsed using the AST module.

    Args:
        file_path (str): Path to the Python source file.

    Returns:
        bool: True if the file can be parsed without syntax errors, False otherwise.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
         
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=SyntaxWarning)
            ast.parse(source, filename=file_path)
        return True
    except (SyntaxError, UnicodeDecodeError, ValueError) as e:
        return False