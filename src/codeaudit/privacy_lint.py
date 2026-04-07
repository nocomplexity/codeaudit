"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. 

EGRESS DETECTION LOGIC - see docs
"""
# from codeaudit.api_interfaces import version
from codeaudit import __version__
from codeaudit.filehelpfunctions import (
    get_filename_from_path,
    collect_python_source_files,
    is_ast_parsable,
    read_in_source_file,
)
from codeaudit.pypi_package_scan import get_pypi_download_info, get_package_source


import ast
from pathlib import Path
import datetime
import re


from importlib.resources import files

SECRETS_LIST = files("codeaudit.data").joinpath("secretslist.txt")


def data_egress_scan(input_path):
    """Scans Python file or a PyPI package for potential privacy leaks.

    This function analyzes Python code for possible privacy-related issues
    (which often overlap with security weaknesses). The input can be:
    - A local directory containing a Python package
    - A single Python file
    - A PyPI package name (which will be downloaded and scanned)

    Depending on the input type, the function performs an AST-based scan
    and returns structured metadata along with scan results.

    Args:
        input_path (str): Path to a local directory, path to a Python
            file, or the name of a PyPI package to scan.

    Returns:
        dict: A dictionary containing scan metadata and results. The
        structure varies depending on the input:
            - For a directory or PyPI package, results include package-level
              privacy findings.
            - For a single Python file, results include file-level privacy
              findings.
            - If the input is invalid, an error dictionary is returned with
              an `"Error"` key.

    Raises:
        None: All errors are handled internally and reported in the
        returned dictionary.
    """
    file_output = {}
    file_path = Path(input_path)
    ca_version_info = {"name": "Python_Code_Audit", "version": __version__}
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    output = ca_version_info | {"generated_on": timestamp_str}
    # Check if the input is a valid directory or a single valid Python file
    if file_path.is_dir():  # local directory scan
        package_name = get_filename_from_path(input_path)
        output |= {"package_name": package_name}
        spycheck_output = _codeaudit_directory_spyscan(input_path)
        output |= spycheck_output
        return output
    elif (
        file_path.suffix.lower() == ".py"
        and file_path.is_file()
        and is_ast_parsable(input_path)
    ):  # check on parseable single Python file
        # do a file spy check
        name_of_file = get_filename_from_path(input_path)
        name_dict = {"FileName": name_of_file}
        spycheck_output = spy_check(input_path)
        file_output["0"] = (
            spycheck_output  # there is only 1 file , so index 0 equals as for package to make functionality that use the output that works on the dict or json can equal for a package or a single file!
        )
        output |= {"file_name": name_dict, "file_privacy_check": file_output}
        return output
    elif pypi_data := get_pypi_download_info(input_path):
        package_name = (
            input_path  # The variable input_path is now equal to the package name
        )
        url = pypi_data["download_url"]
        release = pypi_data["release"]
        if url is not None:
            src_dir, tmp_handle = get_package_source(url)
            output |= {"package_name": package_name, "package_release": release}
            try:
                spycheck_output = _codeaudit_directory_spyscan(src_dir)
                output |= spycheck_output
            finally:
                # Cleaning up temp directory
                tmp_handle.cleanup()  # deletes everything from temp directory
            return output
    else:
        # Its not a directory nor a valid Python file:
        return {
            "Error": "File is not a *.py file, does not exist or is not a valid directory path towards a Python package."
        }


def spy_check(file):
    """runs the AST function to get spy info"""
    code = read_in_source_file(file)
    spy_output = collect_secret_values(code)
    name_of_file = get_filename_from_path(file)
    output = {"file_name": name_of_file, "privacy_check_result": spy_output}
    return output


def _codeaudit_directory_spyscan(input_path):
    """Performs a spyscan on a local directory
    Function is also used with scanning directory PyPI.org packages, since in that case a tmp directory is used
    """
    output = {}
    file_output = {}
    files_to_check = collect_python_source_files(input_path)
    if len(files_to_check) > 1:
        for i, file in enumerate(files_to_check):
            file_output[i] = spy_check(file)
        output |= {"file_privacy_check": file_output}
        return output
    else:
        output_msg = f"Directory path {input_path} contains no Python files."
        return {"Error": output_msg}


def load_secrets_list(filename=SECRETS_LIST):
    """
    Load secrets from SECRETS_LIST and return a list of lines,
    excluding empty lines and lines starting with '#'.
    """
    secrets_patterns = []

    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            secrets_patterns.append(line.lower())  # lower all patterns

    return secrets_patterns


def match_secret(secrets, name, value):
    """
    Check whether a name or value contains a secret.

    Assumptions:
    - `secrets` are already lowercased.

    Matching rules (in priority order):
    1. Whole-word match in name
    2. Whole-word match in value

    Returns:
        The matching secret (lowercased) if found, otherwise None.
    """
    name_lower = str(name).lower()
    value_lower = str(value).lower()

    # Shorter secrets first to preserve original behavior
    for secret_tag in sorted(secrets, key=len):
        pattern = re.compile(rf"\b{re.escape(secret_tag)}\b")

        if pattern.search(name_lower) or pattern.search(value_lower):
            return secret_tag

    return None


def has_privacy_findings(data):
    """
    Returns True if at least one file has a non-empty
    'privacy_check_result' list, otherwise False.
    """
    filesscanned = data.get("file_privacy_check", {})

    for file_info in filesscanned.values():
        results = file_info.get("privacy_check_result")
        if results and len(results) > 0:
            return True

    return False


def count_privacy_check_results(data):
    """
    Count total number of findings across all files,
    only where privacy_check_result is non-empty.
    """
    file_checks = data.get("file_privacy_check", {})

    return sum(
        len(entry.get("privacy_check_result", []))
        for entry in file_checks.values()
        if isinstance(entry, dict) and entry.get("privacy_check_result")
    )


def collect_secret_values(source_code, secrets_file=SECRETS_LIST):
    """Scan Python source code for potential secret values indicating telemetry or data exfiltration.
    Duplicate line results are filtered out.
    """
    secrets = load_secrets_list(secrets_file)
    results = []
    seen_keys = set()
    seen_lines = set()  # Track line contents to filter duplicates
    source_lines = source_code.splitlines()

    # -------------------------
    # Parse AST and detect aliases
    # -------------------------
    tree = ast.parse(source_code)
    aliases = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.asname:
                    aliases[n.asname] = n.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for n in node.names:
                full = f"{module}.{n.name}" if module else n.name
                if n.asname:
                    aliases[n.asname] = full

    # -------------------------
    # Helpers
    # -------------------------
    def get_constant(node):
        return getattr(node, "value", None)

    def is_os_environ(node):
        return (
            getattr(getattr(node, "value", None), "attr", None) == "environ"
            and getattr(
                getattr(getattr(node, "value", None), "value", None), "id", None
            )
            == "os"
        )

    def get_target_repr(node):
        if hasattr(node, "id"):
            return node.id
        if hasattr(node, "attr") or hasattr(node, "slice"):
            return ast.unparse(node)
        return None

    def classify_value(node):
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if hasattr(node, "slice"):
            if is_os_environ(node):
                return get_constant(node.slice)
            return ast.unparse(node)
        if hasattr(node, "func") and getattr(node, "args", None):
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant):
                return first_arg.value
        if hasattr(node, "id") or hasattr(node, "attr"):
            return ast.unparse(node)
        return ast.unparse(node)

    def get_original_line(node):
        lineno = getattr(node, "lineno", None)
        if lineno is None:
            return None
        lines = []
        if lineno > 1:
            lines.append(source_lines[lineno - 2].rstrip())
        if 1 <= lineno <= len(source_lines):
            lines.append(source_lines[lineno - 1].rstrip())
        if lineno < len(source_lines):
            lines.append(source_lines[lineno].rstrip())
        return "\n".join(lines)

    def get_call_name(node):
        func = getattr(node, "func", None)
        if isinstance(func, ast.Attribute):
            base = ast.unparse(func.value)
            base = aliases.get(base, base)
            return f"{base}.{func.attr}"
        if isinstance(func, ast.Name):
            return aliases.get(func.id, func.id)
        return None

    def add_value(name, value_node, node, call=None):
        value = classify_value(value_node)
        matched = match_secret(secrets, name, value)
        if matched is None:
            return

        lineno = getattr(node, "lineno", None)
        line_content = get_original_line(node)

        key = (lineno, matched, call)

        # Skip duplicate keys or duplicate line content
        if key in seen_keys or line_content in seen_lines:
            return

        seen_keys.add(key)
        seen_lines.add(line_content)

        results.append(
            {
                "lineno": lineno,
                "code": line_content,
                "matched": matched,
                "call": call,
            }
        )

    # -------------------------
    # Walk AST
    # -------------------------
    for node in ast.walk(tree):
        # Assignments
        for target in getattr(node, "targets", []):
            name = get_target_repr(target)
            if name:
                add_value(name, getattr(node, "value", None), node)

        # Annotated assignments
        if isinstance(node, ast.AnnAssign):
            name = get_target_repr(node.target)
            if name:
                add_value(name, getattr(node, "value", None), node)

        # Function calls
        if isinstance(node, ast.Call):
            call_name = get_call_name(node)
            # Keyword arguments
            for kw in node.keywords:
                if kw.arg:
                    add_value(kw.arg, kw.value, kw, call_name)
            # Positional arguments
            for arg in node.args:
                add_value(None, arg, node, call_name)

    return sorted(results, key=lambda item: item["lineno"])
