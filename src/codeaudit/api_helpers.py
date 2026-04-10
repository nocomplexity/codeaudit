"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

Function to create nice APIs. So API helper functions.
"""

import pandas as pd

from codeaudit.api_interfaces import get_modules, get_overview, _build_weakness_details
from codeaudit.checkmodules import get_all_modules
from codeaudit.filehelpfunctions import (
    collect_python_source_files,
    get_filename_from_path,
)
from codeaudit.security_checks import perform_validations
from codeaudit.suppression import filter_sast_results
from codeaudit.totals import overview_per_file


def _codeaudit_scan_wasm(filename, nosec_flag):
    """Internal helper function to do a SAST scan on a single file (WASM-safe)
    filename is full filename, including path
    """
    name_of_file = get_filename_from_path(filename)

    try:
        # Run SAST scan
        if not nosec_flag:
            sast_data = perform_validations(filename)
        else:
            unfiltered_scan_output = perform_validations(filename)
            sast_data = filter_sast_results(unfiltered_scan_output)

        # Defensive extraction
        sast_data_results = sast_data.get("result", {})
        details = _build_weakness_details(sast_data_results, filename)
        return {"file_name": name_of_file, "sast_result": details}
    except Exception as e:
        # WASM-safe: never crash entire scan because of one file
        return {"file_name": name_of_file, "sast_result": {}, "error": str(e)}


def _codeaudit_directory_scan_wasm(input_path, nosec_flag):
    """
    Performs a scan on a directory (WASM/Pyodide safe).
    Works for extracted PyPI packages.
    """

    output = {}
    file_output = {}

    try:
        files_to_check = collect_python_source_files(input_path)
    except Exception as e:
        return {"Error": f"Failed to collect Python files: {str(e)}"}

    if not files_to_check:
        return {"Error": f"Directory path {input_path} contains no Python files."}
    # Package-level metadata (safe-guarded)
    try:
        modules_discovered = get_all_modules(input_path)
    except Exception:
        modules_discovered = {}

    try:
        package_overview = get_overview(input_path)
    except Exception:
        package_overview = {}

    output |= {
        "statistics_overview": package_overview,
        "module_overview": modules_discovered,
    }
    # File scanning
    for i, file in enumerate(files_to_check):
        try:
            file_information = overview_per_file(file)
        except Exception:
            file_information = {}

        try:
            module_information = get_modules(file)
        except Exception:
            module_information = {}

        scan_output = _codeaudit_scan_wasm(file, nosec_flag)

        # Ensure merge never crashes
        try:
            file_output[i] = file_information | module_information | scan_output
        except Exception:
            # fallback (extreme edge case)
            file_output[i] = {
                "file_name": get_filename_from_path(file),
                "error": "Failed to merge scan results",
            }

    output |= {"file_security_info": file_output}

    return output
