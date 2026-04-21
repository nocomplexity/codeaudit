"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.


Public API functions for Python Code Audit aka codeaudit on pypi.org
"""

import datetime
import json
import html
import platform
from collections import Counter
from pathlib import Path

import altair as alt
import pandas as pd

from codeaudit.__about__ import __version__


from codeaudit.checkmodules import (
    check_module_vulnerability,
    get_all_modules,
    get_imported_modules_by_file,
    get_standard_library_modules,
)
from codeaudit.filehelpfunctions import (
    collect_python_source_files,
    get_filename_from_path,
    is_ast_parsable,
)
from codeaudit.privacy_lint import data_egress_scan
from codeaudit.pypi_package_scan import get_package_source, get_pypi_download_info
from codeaudit.security_checks import ast_security_checks, perform_validations
from codeaudit.suppression import filter_sast_results
from codeaudit.totals import (
    get_statistics,
    overview_count,
    overview_per_file,
    total_modules,
)

def version():
    """Returns the version of Python Code Audit - WASM safe"""
    ca_version = __version__
    return {"name": "Python_Code_Audit", "version": ca_version}



def filescan(input_path, nosec=False):
    """
    Scan a Python source file, a local directory, or a **PyPI package** from PyPI.org for
    security weaknesses and return the results as a JSON-serializable
    dictionary.

    This API function works on:

    - **Local directory**: Recursively scans all supported Python files in the
      directory.
    - **Single Python file**: Scans the file if it exists and can be parsed
      into an AST.
    - **PyPI package** on PyPI.org: Downloads the
      source distribution from PyPI, scans it, and cleans up temporary files.

    The returned output always includes Python Code Audit version information and a
    generation timestamp. For consistency, single-file scans are normalized
    to match the structure of directory/package scans.

    **Note:**
    The filescan command does NOT include all directories. This is done on purpose!
    The following directories are skipped by default:

    - `/docs`
    - `/docker`
    - `/dist`
    - `/tests`
    - all directories that start with . (dot) or _ (underscore)

    But you can easily change this if needed!

    Args:
        input_path (str): One of the following:
            - Path to a local directory containing Python code.
            - Path to a single ``.py`` file.
            - Name of a package available on PyPI.

    Returns:
        dict: A JSON-serializable dictionary containing scan results and
        metadata. The structure varies slightly depending on the scan type,
        but always includes:
            - Version information from ``version()``.
            - ``generated_on`` timestamp (``YYYY-MM-DD HH:MM``).
            - Package or file-level security findings.

        If the input cannot be interpreted as a valid directory, Python file,
        or PyPI package, a dictionary with an ``"Error"`` key is returned.

    Raises:
        None explicitly. Any unexpected exceptions are allowed to propagate
        unless handled by downstream callers.

    Example:
        >>> result = filescan("example_package")
        >>> result["package_name"]

    """
    file_output = {}
    file_path = Path(input_path)
    ca_version_info = version_info()
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    output = ca_version_info | {"generated_on": timestamp_str}
    # Check if the input is a valid directory or a single valid Python file
    if file_path.is_dir():  # local directory scan
        package_name = get_filename_from_path(input_path)
        output |= {"package_name": package_name}
        scan_output = _codeaudit_directory_scan(input_path, nosec_flag=nosec)
        output |= scan_output
        return output
    elif (
        file_path.suffix.lower() == ".py"
        and file_path.is_file()
        and is_ast_parsable(input_path)
    ):  # check on parseable single Python file
        # do a file check
        file_information = overview_per_file(input_path)
        module_information = get_modules(input_path)  # modules per file
        scan_output = _codeaudit_scan(input_path, nosec_flag=nosec)
        file_output["0"] = (
            file_information | module_information | scan_output
        )  # there is only 1 file , so index 0 equals as for package to make functionality that use the output that works on the dict or json can equal for a package or a single file!
        output |= {"file_security_info": file_output}
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
                scan_output = _codeaudit_directory_scan(src_dir, nosec_flag=nosec)
                output |= scan_output
            finally:
                # Cleaning up temp directory
                tmp_handle.cleanup()  # deletes everything from temp directory
            return output
    else:
        # Its not a directory nor a valid Python file:
        return {
            "Error": "File is not a *.py file, does not exist or is not a valid directory path towards a Python package."
        }


def _codeaudit_scan(filename, nosec_flag):
    """Internal helper function to do a SAST scan on a single file
    To scan a file, or Python package using the API interface, use the `filescan` API call!
    """
    # get the file name
    name_of_file = get_filename_from_path(filename)
    if not nosec_flag:  # no filtering on reviewed items with markers in code
        sast_data = perform_validations(filename)
    else:
        unfiltered_scan_output = perform_validations(
            filename
        )  # scans for weaknesses in the file
        sast_data = filter_sast_results(unfiltered_scan_output)
    sast_data_results = sast_data.get("result", {})
    details = _build_weakness_details(sast_data_results, filename)
    output = {"file_name": name_of_file, "sast_result": details}
    return output


def _codeaudit_directory_scan(input_path, nosec_flag):
    """Performs a scan on a local directory
    Function is also used with scanning directory PyPI.org packages, since in that case a tmp directory is used
    """
    output = {}
    file_output = {}
    files_to_check = collect_python_source_files(input_path)
    if len(files_to_check) > 1:
        modules_discovered = get_all_modules(
            input_path
        )  # all modules for the package aka directory
        package_overview = get_overview(input_path)
        output |= {
            "statistics_overview": package_overview,
            "module_overview": modules_discovered,
        }
        for i, file in enumerate(files_to_check):
            file_information = overview_per_file(file)
            module_information = get_modules(file)  # modules per file
            scan_output = _codeaudit_scan(file, nosec_flag)
            file_output[i] = file_information | module_information | scan_output
        output |= {"file_security_info": file_output}
        return output
    else:
        output_msg = f"Directory path {input_path} contains no Python files."
        return {"Error": output_msg}


def save_to_json(sast_result, filename="codeaudit_output.json"):
    """
    Save a SAST result (dict or serializable object) to a JSON file.

    Args:
        sast_result (dict or list): The data to be saved as JSON.
        filename (str, optional): The file path to save the JSON data.
            Defaults to "codeaudit_output.json".

    Returns:
        Path: The absolute path of the saved file, or None if saving failed.
    """
    filepath = Path(filename).expanduser().resolve()

    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)  # ensure directory exists
        with filepath.open("w", encoding="utf-8") as f:
            json.dump(sast_result, f, indent=2, ensure_ascii=False)
        return
    except (TypeError, ValueError) as e:
        print(f"[Error] Failed to serialize data to JSON: {e}")
    except OSError as e:
        print(f"[Error] Failed to write file '{filepath}': {e}")


def read_input_file(filename, safe_directory="data_folder"):
    """
    Securely read a Python CodeAudit JSON file and return its contents as a dictionary.

    Args:
        filename: Path to the JSON file (str or Path).
        safe_directory: Base directory considered "safe" for reading files.

    Returns:
        dict: The contents of the JSON file.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file is outside the allowed safe directory.
        json.JSONDecodeError: If the file is not valid JSON.
    """
    # Convert to Path object
    file_path = Path(filename).expanduser().resolve()
    base_dir = Path(safe_directory).expanduser().resolve()

    # Security check: ensure the file is within the safe directory
    if not file_path.is_relative_to(base_dir):
        raise PermissionError(
            f"Access denied: {file_path} is outside the safe directory"
        )

    # Ensure the file exists and is a file
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found or not a regular file: {file_path}")

    try:
        # Read JSON content safely
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in file: {file_path}", e.doc, e.pos)


def get_weakness_counts(input_file, nosec=False):
    """
    Analyze a Python file or package and count occurrences of code weaknesses.
    """
    # Assuming filescan is imported from codeaudit.api_interfaces
    scan_result = filescan(input_file, nosec)

    if not isinstance(scan_result, dict):
        raise ValueError("filescan() did not return a valid result dictionary")

    if "Error" in scan_result:
        raise ValueError(scan_result["Error"])

    file_security_info = scan_result.get("file_security_info")
    if not isinstance(file_security_info, dict):
        return {}

    counter = Counter()

    for file_info in file_security_info.values():
        if not isinstance(file_info, dict):
            continue

        sast_result = file_info.get("sast_result", {})
        if not isinstance(sast_result, dict):
            continue

        # Based on your data: sast_result keys are line numbers (e.g., 171)
        # and values are dicts containing the 'validation' type.
        for issue_details in sast_result.values():
            if isinstance(issue_details, dict):
                # We use the 'validation' field to identify the type of weakness
                weakness_type = issue_details.get("validation", "Unknown")
                counter[weakness_type] += 1

    return dict(counter)


def get_modules(filename):
    """Gets modules of a Python file"""
    modules_found = get_imported_modules_by_file(filename)
    return modules_found


def get_overview(input_path):
    """Retrieves the security relevant statistics of a Python package(directory) or of a single Python

    Based on the input path, call the overview function and return the result in a dict

    Args:
        input_path: Directory path of the package to use


    Returns:
        dict: Returns the overview statistics in DICT format
    """
    file_path = Path(input_path)
    if file_path.is_dir():  # only for valid parsable Python files
        files_to_check = collect_python_source_files(input_path)
        if len(files_to_check) > 1:
            statistics = get_statistics(input_path)
            modules = total_modules(input_path)
            df = pd.DataFrame(statistics)
            df["Std-Modules"] = modules[
                "Std-Modules"
            ]  # Needed for the correct overall count
            df["External-Modules"] = modules[
                "External-Modules"
            ]  # Needed for the correct overall count
            overview_df = overview_count(df)  # create the overview Dataframe
            dict_overview = overview_df.to_dict(orient="records")[
                0
            ]  # The overview Dataframe has only one row
            return dict_overview
        else:
            output_msg = f"Directory path {input_path} contains no Python files."
            return {"Error": output_msg}
    elif (
        file_path.suffix.lower() == ".py"
        and file_path.is_file()
        and is_ast_parsable(input_path)
    ):
        security_statistics = overview_per_file(input_path)
        return security_statistics
    else:
        # Its not a directory nor a valid Python file:
        return {
            "Error": "File is not a *.py file, does not exist or is not a valid directory path to a Python package."
        }


def get_default_validations():
    """Retrieve the default implemented security validations.

    This function collects the built-in Static Application Security Testing (SAST)
    validations applied to standard Python modules. It retrieves the validation
    definitions, converts them into a serializable format, and enriches the result
    with generation metadata.

    The returned structure is intended to be consumed by reporting, API, or
    documentation layers.

    Returns:
        dict: A dictionary containing generation metadata and a list of security
        validations. The dictionary has the following structure:

        {
            "<metadata_key>": <metadata_value>,
            ...,
            "validations": [
                {
                    "<field>": <value>,
                    ...
                },
                ...
            ]
        }


    **Notes**:

        - Requires Python 3.9 or later due to use of the dictionary union operator (`|`).
        - The `validations` list is derived from a pandas DataFrame using
          `to_dict(orient="records")`.
    """
    df = ast_security_checks()
    result = df.to_dict(orient="records")
    output = _generation_info() | {"validations": result}
    return output


def _generation_info():
    """Internal function to retrieve generation info for APIs output"""
    ca_version_info = version_info()
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    output = ca_version_info | {"generated_on": timestamp_str}
    return output


def platform_info():
    """Get Python platform information - Python version and Python runtime interpreter used.
    Args:
        none

    Returns:
        dict: Overview of implemented security SAST validation on Standard Python modules
    """
    python_version = platform.python_version()
    platform_implementation = platform.python_implementation()
    output = {
        "python_version": python_version,
        "python_implementation": platform_implementation,
    }
    return output


def get_psl_modules():
    """Retrieves a list of  collection of Python modules that are part of a Python distribution aka standard installation

    Returns:
        dict: Overview of PSL modules in the Python version used.

    """
    psl_modules = get_standard_library_modules()
    output = _generation_info() | platform_info() | {"psl_modules": psl_modules}
    return output


def get_module_vulnerability_info(module):
    """
    Retrieves vulnerability information for an external module using the OSV Database.

    Args:
        module (str): Name of the module to query.

    Returns:
        dict: Generation metadata combined with OSV vulnerability results.
    """
    vuln_info = check_module_vulnerability(module)
    key_string = f"{module}_vulnerability_info"
    output = _generation_info() | {key_string: vuln_info}
    return output


def egress_check(input_path):
    """Scan Python code for potential data egress or privacy leaks.

    This function performs a static analysis of Python source code to
    detect patterns that may indicate privacy or data-egress risks.
    The analysis is based on an Abstract Syntax Tree (AST) inspection
    of the provided source.

    The input can refer to:
      - A local directory containing a Python package
      - A single Python file
      - A PyPI package name (the package will be downloaded and scanned)

    Depending on the input type, the function performs a file-level or
    package-level scan and returns structured metadata together with
    the detected findings.

    Args:
        input_path (str): Location of the Python code to analyze. This can be:
            - Path to a local Python package directory.
            - Path to a single `.py` file.
            - Name of a package published on PyPI.

    Returns:
        dict: Dictionary containing scan metadata and analysis results.
        The dictionary always includes basic metadata such as the tool
        name, version, and generation timestamp. Additional fields
        depend on the input type:

        **Directory or PyPI package input**
            - ``package_name``: Name of the scanned package.
            - ``package_release`` (PyPI only): Package version.
            - Package-level privacy findings.

        **Single file input**
            - ``file_name``: Name of the scanned file.
            - ``file_privacy_check``: Results of the file-level analysis.

        **Invalid input**
            - ``{"Error": "<message>"}``

    Raises:
        None: All errors are handled internally and reported in the
        returned dictionary instead of raising exceptions.


    **Notes:**

    - The scan uses static AST analysis and does **not execute code**.
    - PyPI packages are downloaded to a temporary directory before scanning.
    - Temporary directories are automatically removed after the scan.
    - Only syntactically valid Python files that can be parsed into an AST
      are analyzed.

    Examples for API use:

    1. Scan a local Python file:

        >>> data_egress_scan("script.py")

    2. Scan a local package directory:

        >>> data_egress_scan("./my_package")

    3. Scan a package from PyPI:

        >>> data_egress_scan("requests")

    """
    output = data_egress_scan(input_path)
    return output


def get_construct_counts(input_file):
    """
    Analyze a Python file or package(directory) and count occurrences of code constructs (aka weaknesses).

    This function uses `filescan` API call to retrieve security-related information
    about the input file. This returns a dict. Then it counts how many times each code construct
    appears across all scanned files.

    Args:
        input_file (str): Path to the file or directory(package) to scan.

    Returns:
        dict: A dictionary mapping each construct name (str) to the total
              number of occurrences (int) across all scanned files.

    Notes:
        - The `filescan` function is expected to return a dictionary with
          a 'file_security_info' key, containing per-file information.
        - Each file's 'sast_result' should be a dictionary mapping
          construct names to lists of occurrences.
    """
    scan_result = filescan(input_file)
    counter = Counter()

    for file_info in scan_result.get("file_security_info", {}).values():
        sast_result = file_info.get("sast_result", {})
        for (
            construct,
            occurence,
        ) in (
            sast_result.items()
        ):  # occurence is times the construct appears in a single file
            counter[construct] += len(occurence)

    return dict(counter)


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
                "code": code_snippet,
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
            return (str(row.get("severity", "unknown")), str(row.get("info", "")))

        # Controlled fallback (avoid overly broad matching)
        if "extractall" in error:
            fallback_rows = df[df["construct"] == "tarfile.TarFile"]
            if not fallback_rows.empty:
                row = fallback_rows.iloc[0]
                return (str(row.get("severity", "unknown")), str(row.get("info", "")))

    except Exception:
        return DEFAULT

    # Safe fallback instead of exit()
    return DEFAULT


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

    snippet_lines = [l.rstrip("\n") for l in snippet_lines if l.strip() != ""]

    # Escape HTML to prevent injection
    escaped_lines = [html.escape(l) for l in snippet_lines]

    code_lines = (
        "<pre><code class='language-python'>"
        + "\n".join(escaped_lines)
        + "</code></pre>"
    )

    return code_lines
