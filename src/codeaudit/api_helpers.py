"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 

Function to create nice APIs. So API helper functions.
"""

import pandas as pd
import html

from codeaudit.security_checks import ast_security_checks

def _collect_issue_lines(filename, line, context=1):
    """
    Safely extract source code lines around a specific line number for display.

    Args:
        filename (str): Path to the Python source file.
        line (int): Target line number (1-based).
        context (int, optional): Number of lines of context before and after the target line. Defaults to 1.

    Returns:
        str: HTML-formatted code snippet with <pre><code> wrapper. Returns empty string on failure.
    """
    # Validate inputs
    if not isinstance(filename, str) or not filename:
        return ""
    if not isinstance(line, int) or line <= 0:
        return ""

    try:
        with open(filename, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return ""

    # Calculate safe slice indices
    start = max(line - context - 1, 0)  # zero-based
    end = min(line + context, len(lines))

    snippet_lines = lines[start:end]
    
    snippet_lines = [l.rstrip('\n') for l in snippet_lines if l.strip() != ""]

    # Escape HTML to prevent injection
    escaped_lines = [html.escape(l) for l in snippet_lines]

    code_lines = "<pre><code class='language-python'>" + "\n".join(escaped_lines) + "</code></pre>"

    return code_lines


def _get_test_info(error):
    """
    Retrieve severity and info text for a given SAST error identifier.

    Args:
        error (str): Identifier to match against the 'construct' column.

    Returns:
        tuple[str, str]: (severity, info_text). Defaults to ('unknown', '')
        if no match is found or an error occurs.
    """
    DEFAULT = ("unknown", "")
    # Validate input
    if not isinstance(error, str) or not error:
        return DEFAULT

    try:
        df = ast_security_checks()
    except Exception:
        return DEFAULT

    # Validate expected structure
    required_columns = {"construct", "severity", "info"}
    if not hasattr(df, "columns") or not required_columns.issubset(df.columns):
        return DEFAULT

    try:
        # Exact match
        found_rows = df[df["construct"] == error]
        if not found_rows.empty:
            row = found_rows.iloc[0]
            return (
                str(row.get("severity", "unknown")),
                str(row.get("info", ""))
            )

        # Controlled fallback (avoid overly broad matching)
        if "extractall" in error:
            fallback_rows = df[df["construct"] == "tarfile.TarFile"]
            if not fallback_rows.empty:
                row = fallback_rows.iloc[0]
                return (
                    str(row.get("severity", "unknown")),
                    str(row.get("info", ""))
                )

    except Exception:
        return DEFAULT

    # Safe fallback instead of exit()
    return DEFAULT


def _build_weakness_details(sastresult, filename_location):
    """
    Builds a mapping of line numbers to SAST issue details.

    Processes static analysis results into a dictionary keyed by line number,
    including severity, description, and code snippets. Handles invalid input,
    duplicate line issues, and limits total processed entries for safety.

    Args:
        sastresult (dict): Mapping of issue identifiers to iterable line numbers.
        filename_location (str): Path to the source file for extracting code snippets.

    Returns:
        dict: Dictionary keyed by line number containing issue detail dict(s).
              If multiple issues exist on the same line, the value is a list.
    """
    if not isinstance(sastresult, dict) or not sastresult:
        return {}

    # Optional: basic path safety check (adjust as needed)
    if not isinstance(filename_location, str) or ".." in filename_location:
        return {}

    result = {}
    MAX_ISSUES = 10000  # prevent abuse / runaway loops
    issue_count = 0

    for error_str, line_numbers in sastresult.items():

        # Validate key
        if not isinstance(error_str, str):
            continue

        # Validate line_numbers
        if not isinstance(line_numbers, (list, tuple, set)):
            continue

        # Safe retrieval of metadata
        try:
            severity, info_text = _get_test_info(error_str)
        except Exception:
            severity, info_text = "unknown", ""

        for line_num in line_numbers:

            # Limit total processed issues
            issue_count += 1
            if issue_count > MAX_ISSUES:
                break

            # Validate line number
            if not isinstance(line_num, int) or line_num <= 0:
                continue

            # Safe code extraction
            try:
                code_snippet = _collect_issue_lines(filename_location, line_num)
            except Exception:
                code_snippet = ""

            entry = {
                "line": line_num,
                "validation": error_str,
                "severity": severity,
                "info": info_text,
                "code": code_snippet
            }

            # Handle multiple issues on same line
            if line_num in result:
                # Convert to list if needed
                if isinstance(result[line_num], list):
                    result[line_num].append(entry)
                else:
                    result[line_num] = [result[line_num], entry]
            else:
                result[line_num] = entry

        if issue_count > MAX_ISSUES:
            break

    return result


# def _build_weakness_details(sastresult, filename_location):
#     """Convert the list of (error, lines) into a flat dict keyed by line number."""
#     if not sastresult or not isinstance(sastresult, dict):
#         return {}
    
#     result = {}
#     for error_str, line_numbers in sastresult.items():            
#         # Get severity and info once per error type (more efficient)
#         severity, info_text = get_test_info(error_str)
        
#         for line_num in line_numbers:
#             code_snippet = collect_issue_lines(filename_location, line_num)
            
#             result[line_num] = {
#                 "line": line_num,
#                 "validation": error_str,
#                 "severity": severity,
#                 "info": info_text,
#                 "code": code_snippet
#             }
    
#     return result
