"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.


WASM Dashboard version of codeaudit - limited functionality -
"""

import asyncio
import datetime
import inspect
import json
import sys

import panel as pn

pn.extension("vega")

from codeaudit.dashboard_reports import (
    create_statistics_overview,
    get_disclaimer_text,
    get_info_text,
    report_sast_results,
    report_used_modules,
)

from codeaudit.altairplots import (
    ast_nodes_overview,
    complexity_heatmap,
    lines_of_code_overview,
    module_count_barchart,
    module_distribution_view,
    sast_files_overview,
    weaknesses_overview,
    weaknesses_radial_overview,
)

from codeaudit.api_helpers import _codeaudit_directory_scan_wasm
from codeaudit.api_interfaces import get_package_source, version, package_imports

# --- Environment Detection ---
IS_PYODIDE = "pyodide" in sys.modules


async def get_pypi_package_info_wasm(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    if IS_PYODIDE:
        from pyodide.http import pyfetch

        try:
            response = await pyfetch(url)
            if not response.ok:
                return False
            return await response.json()
        except:
            return False
    else:
        import urllib.request

        try:
            with urllib.request.urlopen(url) as response:
                return json.loads(response.read().decode("utf-8"))
        except:
            return False


async def get_pypi_download_info_wasm(package_name):
    data = await get_pypi_package_info_wasm(package_name)
    if not data or "info" not in data:
        return False

    version_str = data.get("info", {}).get("version")
    releases = data.get("releases", {}).get(version_str, [])

    for file_info in releases:
        if file_info.get("packagetype") == "sdist" and file_info.get("url").endswith(
            ".tar.gz"
        ):
            return {"download_url": file_info.get("url"), "release": version_str}
    return False


async def get_package_source_wasm(url):
    import os
    import tempfile
    from pyodide.http import pyfetch

    tmpdir_obj = None
    try:
        response = await pyfetch(url)
        if not response.ok:
            return None

        tmpdir_obj = tempfile.TemporaryDirectory(prefix="codeaudit_")
        temp_dir = tmpdir_obj.name
        extract_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_dir, exist_ok=True)

        # Recommended Pyodide way – works reliably in MEMFS
        await response.unpack_archive(extract_dir=extract_dir, format="gztar")

        # Locate the actual package root (same logic as before)
        entries = os.listdir(extract_dir)
        directories = [
            os.path.join(extract_dir, entry)
            for entry in entries
            if os.path.isdir(os.path.join(extract_dir, entry))
        ]
        files = [
            entry
            for entry in entries
            if os.path.isfile(os.path.join(extract_dir, entry))
        ]

        if len(directories) == 1 and not files:
            source_dir = directories[0]
        else:
            source_dir = extract_dir

        # Verify that the extracted source contains Python files
        has_python_files = any(
            filename.endswith(".py")
            for root, _, filenames in os.walk(source_dir)
            for filename in filenames
        )

        if not has_python_files:
            print(f"WASM extraction found no .py files under {source_dir}")
            tmpdir_obj.cleanup()
            return None

        return source_dir, tmpdir_obj

    except Exception as e:
        print(f"WASM fetch/extraction error: {e}")
        if tmpdir_obj is not None:
            tmpdir_obj.cleanup()
        return None


# --- Logic for SAST scan to be WASM safe---
async def filescan_wasm(input_path, nosec=False):
    """
    WASM-compatible PyPI-only version of filescan function.
    Matches the behaviour of the original implementation for PyPI scans.

    PYPI PACKAGE ONLY (for now)
    """
    ca_version_info = version()
    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M")
    output = ca_version_info | {"generated_on": timestamp_str}
    pypi_data = await get_pypi_download_info_wasm(input_path)

    if pypi_data:
        package_name = input_path
        url = pypi_data.get("download_url")
        release = pypi_data.get("release")

        if url is not None:
            # WASM-safe
            if IS_PYODIDE:
                decoded_res = await get_package_source_wasm(url)
            else:
                source_res = get_package_source(url)

                if inspect.isawaitable(source_res):
                    decoded_res = await source_res
                else:
                    decoded_res = source_res
            # Validation
            if decoded_res is None:
                return {
                    "Error": f"Could not download or extract package from {url}. "
                    f"This may be due to browser restrictions."
                }

            src_dir, tmp_handle = decoded_res

            # Match original structure EXACTLY
            output |= {
                "package_name": package_name,
                "package_release": release,
            }

            try:
                scan_output = _codeaudit_directory_scan_wasm(src_dir, nosec_flag=nosec)
                output |= scan_output
                # Normalize optional sections before updating them.
                # The WASM scanner may omit these sections for some packages.
                module_overview = output.setdefault(
                    "module_overview",
                    {"core_modules": [], "imported_modules": []},
                )
                if not isinstance(module_overview, dict):
                    module_overview = {
                        "core_modules": [],
                        "imported_modules": [],
                    }
                    output["module_overview"] = module_overview

                # package_imports() can return None when module data is absent.
                correct_imported_modules = package_imports(output) or []
                module_overview["imported_modules"] = correct_imported_modules

                statistics_overview = output.setdefault("statistics_overview", {})
                if not isinstance(statistics_overview, dict):
                    statistics_overview = {}
                    output["statistics_overview"] = statistics_overview
                statistics_overview["External Modules"] = len(correct_imported_modules)
            finally:
                if tmp_handle:
                    tmp_handle.cleanup()

            return output
    # ---------------------------------------------------------
    return {"Error": "Package not found on PyPI.org."}


# async def filescan_wasm(input_path, nosec=False):
#     """
#     WASM-compatible PyPI-only version of filescan function.
#     Matches the behaviour of the original implementation for PyPI scans.

#     PYPI PACKAGE ONLY (for now)
#     """
#     ca_version_info = version()
#     now = datetime.datetime.now()
#     timestamp_str = now.strftime("%Y-%m-%d %H:%M")
#     output = ca_version_info | {"generated_on": timestamp_str}
#     pypi_data = await get_pypi_download_info_wasm(input_path)

#     if pypi_data:
#         package_name = input_path
#         url = pypi_data.get("download_url")
#         release = pypi_data.get("release")

#         if url is not None:
#             # WASM-safe
#             if IS_PYODIDE:
#                 decoded_res = await get_package_source_wasm(url)
#             else:
#                 source_res = get_package_source(url)

#                 if inspect.isawaitable(source_res):
#                     decoded_res = await source_res
#                 else:
#                     decoded_res = source_res
#             # Validation
#             if decoded_res is None:
#                 return {
#                     "Error": f"Could not download or extract package from {url}. "
#                     f"This may be due to browser restrictions."
#                 }

#             src_dir, tmp_handle = decoded_res

#             # Match original structure EXACTLY
#             output |= {
#                 "package_name": package_name,
#                 "package_release": release,
#             }

#             try:
#                 scan_output = _codeaudit_directory_scan_wasm(src_dir, nosec_flag=nosec)
#                 output |= scan_output
#                 # correct statistics for imported modules and modules count
#                 correct_imported_modules = package_imports(output)
#                 output["module_overview"]["imported_modules"] = correct_imported_modules
#                 output["statistics_overview"]["External Modules"] = len(
#                     correct_imported_modules
#                 )
#             finally:
#                 if tmp_handle:
#                     tmp_handle.cleanup()

#             return output
#     # ---------------------------------------------------------
#     return {"Error": "Package not found on PyPI.org."}


# - END of specific HELPERS to do CA things -#


# --- UI Component Definitions ---
text_input = pn.widgets.TextInput(
    name="Python Package Name", placeholder="Enter PyPI package (e.g., requests)..."
)
nosec_switch = pn.widgets.Switch(
    label="Honor SAST suppressions", value=True, align="center"
)
tooltip = pn.widgets.TooltipIcon(
    value="Disable security markers in the code during the scan"
)

switch_with_tooltip = pn.Row(nosec_switch, tooltip, align="center")

run_button = pn.widgets.Button(name="Start Scan", button_type="primary")
status = pn.pane.Markdown("### Ready to scan.")
result_pane = pn.pane.JSON({}, name="JSON", sizing_mode="stretch_both", depth=-1)
loading = pn.indicators.LoadingSpinner(
    value=False, size=60, color="primary", bgcolor="light", name="Scanning..."
)

placeholder = pn.pane.Markdown(
    "*Run a scan to populate this tab.*",
    sizing_mode="stretch_width",
)

overview_content = pn.Column(placeholder)
modules_content = pn.Column(placeholder)
complexity_content = pn.Column(placeholder)
weaknesses_content = pn.Column(placeholder)
weaknesses_files_content = pn.Column(placeholder)
weaknesses_details_content = pn.Column(placeholder)


tabs = pn.Tabs(
    ("Package Overview", overview_content),
    ("Used Modules", modules_content),
    ("Complexity Insights", complexity_content),
    ("Weaknesses Overview", weaknesses_content),
    ("Weaknesses per file", weaknesses_files_content),
    ("Weaknesses Details", weaknesses_details_content),
    dynamic=True,
    sizing_mode="stretch_both",
)

# --- UI Callback ---


async def run_scan(event):
    package_name = text_input.value.strip()

    if not package_name:
        status.object = "⚠️ Please enter a package name."
        return

    if len(package_name) > 100 or any(c.isspace() for c in package_name):
        status.object = "⚠️ Package name 100 characters or fewer with no spaces."
        return

    # check NOSEC switch from UI
    if nosec_switch.value:
        respect_marker = True
    else:
        respect_marker = False

    # --- UI state updates ---
    run_button.disabled = True
    loading.value = True
    status.object = f"🔄 Scanning: **{package_name}**..."

    try:
        # ✅ Allow UI to update (spinner renders)
        await asyncio.sleep(0.5)

        # ✅ WASM-safe: no threads, no nested event loops
        result = await filescan_wasm(package_name, respect_marker)

        # --- Handle results ---
        if result is None:
            status.object = "❌ Error: Scan failed to return data."

        elif "Error" in result:
            status.object = f"❌ {result['Error']}"
            result_pane.object = result

        else:
            result_pane.object = result
            status.object = f"✅ Scan completed for **{package_name}**"
            # --- Update tabs ---
            overview_content.objects = [create_statistics_overview(result)]

            modules_content.objects = [
                pn.Row(
                    pn.pane.Vega(module_count_barchart(result), show_actions=True),
                    pn.pane.Vega(module_distribution_view(result), show_actions=True),
                ),
                report_used_modules(result),
                pn.Spacer(height=60),
            ]

            complexity_content.objects = [
                pn.pane.Vega(complexity_heatmap(result), show_actions=True),
                pn.pane.Vega(lines_of_code_overview(result), show_actions=True),
                pn.pane.Vega(ast_nodes_overview(result), show_actions=True),
                pn.Spacer(height=60),
            ]

            weaknesses_content.objects = [
                pn.pane.Vega(weaknesses_overview(result), show_actions=True)
            ]

            weaknesses_files_content.objects = [
                pn.pane.Vega(sast_files_overview(result), show_actions=True),
                pn.pane.Vega(weaknesses_radial_overview(result), show_actions=True),
                pn.Spacer(height=60),
            ]

            weaknesses_details_content.objects = [
                report_sast_results(result),
                pn.Spacer(height=60),
            ]

    except Exception as e:
        status.object = f"❌ Exception(!): {str(e)}"

    finally:
        # --- Reset UI state ---
        loading.value = False
        run_button.disabled = False


run_button.on_click(run_scan)

# --- Layout ---

infotext = get_info_text()
disclaimer_text = get_disclaimer_text()

scan_row = pn.Row(run_button, switch_with_tooltip)
# Sidebar layout
ca_sidebar = pn.Column(
    "## Package Code Security Scan",
    text_input,
    scan_row,
    loading,
    status,
    pn.Spacer(height=20),
    infotext,
    pn.Spacer(height=10),
    disclaimer_text,
)

main_pane = pn.Column(tabs, sizing_mode="stretch_both")

app = pn.template.MaterialTemplate(
    header_background="#1E2937",
    title="Python Security Code Audit",
    sidebar=[ca_sidebar],
    main=[main_pane],
)

app.servable()
