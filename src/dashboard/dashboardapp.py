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

# from codeaudit import __version__

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

from codeaudit.api_interfaces import get_package_source, version


from codeaudit.dashboard_reports import (
    create_statistics_overview,
    get_disclaimer_text,
    get_info_text,
    report_sast_results,
    report_used_modules,
)

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
    import gzip
    import tarfile
    import tempfile
    import zlib

    from pyodide.http import pyfetch

    try:
        response = await pyfetch(url)
        if not response.ok:
            return None

        content = await response.bytes()
        content_encoding = response.headers.get("Content-Encoding")

        if content_encoding == "gzip":
            content = gzip.decompress(content)
        elif content_encoding == "deflate":
            content = zlib.decompress(content, -zlib.MAX_WBITS)

        tmpdir_obj = tempfile.TemporaryDirectory(prefix="codeaudit_")
        temp_dir = tmpdir_obj.name

        tar_path = f"{temp_dir}/package.tar.gz"
        with open(tar_path, "wb") as f:
            f.write(content)

        with tarfile.open(tar_path, "r:gz") as tar:
            tar.extractall(path=temp_dir, filter="data")

        return temp_dir, tmpdir_obj

    except Exception as e:
        print(f"WASM fetch error: {e}")
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
            # WASM-safe / Desktop-compatible fetch
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
            finally:
                if tmp_handle:
                    tmp_handle.cleanup()

            return output
    # ---------------------------------------------------------
    return {"Error": "Package not found on PyPI.org."}


# - END of specific HELPERS to do CA things -#


# --- UI Component Definitions ---
text_input = pn.widgets.TextInput(
    name="Python Package Name", placeholder="Enter PyPI package (e.g., requests)..."
)


run_button = pn.widgets.Button(name="Start Scan", button_type="primary")
status = pn.pane.Markdown("### Ready to scan.")
result_pane = pn.pane.JSON({}, name="JSON", sizing_mode="stretch_both", depth=-1)
loading = pn.indicators.LoadingSpinner(
    value=False, size=60, color="primary", bgcolor="light", name="Scanning..."
)


overview_visuals = create_statistics_overview(result_pane.object)

tabs = pn.Tabs(
    ("Package Overview", overview_visuals),
    ("Used Modules", overview_visuals),
    ("Complexity Insights", overview_visuals),
    ("Weaknesses Overview", overview_visuals),
    ("Weaknesses per file", overview_visuals),
    ("Weaknesses Details", overview_visuals),
    dynamic=True,
    sizing_mode="stretch_both",
)

# --- UI Callback ---


async def run_scan(event):
    package_name = text_input.value.strip()

    if not package_name:
        status.object = "⚠️ Please enter a package name."
        return

    # --- UI state updates ---
    run_button.disabled = True
    loading.value = True
    status.object = f"🔄 Scanning: **{package_name}**..."

    try:
        # ✅ Allow UI to update (spinner renders)
        await asyncio.sleep(0.1)

        # ✅ WASM-safe: no threads, no nested event loops
        result = await filescan_wasm(package_name)

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
            tabs[0] = (
                "Package Overview",
                pn.Column(create_statistics_overview(result)),
            )

            tabs[1] = (
                "Used Modules",
                pn.Column(
                    pn.Row(
                        pn.pane.Vega(module_count_barchart(result), show_actions=True),
                        pn.pane.Vega(
                            module_distribution_view(result), show_actions=True
                        ),
                    ),
                    report_used_modules(result),
                    pn.Spacer(height=60),
                ),
            )

            tabs[2] = (
                "Complexity Insights",
                pn.Column(
                    pn.pane.Vega(complexity_heatmap(result), show_actions=True),
                    pn.pane.Vega(lines_of_code_overview(result), show_actions=True),
                    pn.pane.Vega(ast_nodes_overview(result), show_actions=True),
                    pn.Spacer(height=60),
                ),
            )

            tabs[3] = (
                "Weaknesses Overview",
                pn.Column(pn.pane.Vega(weaknesses_overview(result), show_actions=True)),
            )

            tabs[4] = (
                "Weaknesses per file",
                pn.Column(
                    pn.pane.Vega(sast_files_overview(result), show_actions=True),
                    pn.pane.Vega(weaknesses_radial_overview(result), show_actions=True),
                    pn.Spacer(height=60),
                ),
            )

            tabs[5] = (
                "Weaknesses Details",
                pn.Column(
                    report_sast_results(result),
                    pn.Spacer(height=60),
                ),
            )

    except Exception as e:
        status.object = f"❌ Error: {str(e)}"

    finally:
        # --- Reset UI state ---
        loading.value = False
        run_button.disabled = False


run_button.on_click(run_scan)

# --- Layout ---

infotext = get_info_text()
disclaimer_text = get_disclaimer_text()

# Sidebar layout
ca_sidebar = pn.Column(
    "## Package Code Security Scan",
    text_input,
    run_button,
    loading,
    status,
    pn.Spacer(height=20), 
    infotext,
    pn.Spacer(height=10),
    disclaimer_text,
    sizing_mode="stretch_width",
)


main_pane = pn.Column(tabs, sizing_mode="stretch_both")


app = pn.template.MaterialTemplate(
    header_background="#262626",
    title="Python Security Code Audit",
    sidebar=[ca_sidebar],
    main=[main_pane],
)

app.servable()
