"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

API functions: Used for dashboard reporting (Panel / WASM) and notebooks, or to build custom reports.
"""


from codeaudit.__about__ import __version__

SAST_REPORT_CSS = """
<style>
.sast-report {
    font-family: Arial, sans-serif;
    max-width: 1200px;
    margin: 0 auto;   /* centers it */
}

.sast-report table {
    border-collapse: collapse;
    width: 100%;       /* ensures all tables take full container width */
    max-width: 1200px;  /* optional: caps table width */
    margin-top: 10px;
}

.sast-report th, .sast-report td {
    border: 1px solid #ddd;
    padding: 8px;
    vertical-align: top;
}

.sast-report th {
    background-color: #E69F00;
    text-align: left;
}


/* Code blocks */
pre {
    font-size: 1.25em;        
    border-radius: 5px;
    overflow-x: auto;
    width: 100%;
    max-width: 800px;
}

/* Code styling */
.sast-report pre {
    margin: 0;
}

.sast-report pre code.language-python {
    background-color: #2d2d2d;
    color: #f8f8f2;
    font-family: Consolas, Monaco, 'Courier New', monospace;
    font-size: 13px;
    line-height: 1.5;
    padding: 10px;
    border-radius: 6px;
    display: block;
    overflow-x: auto;
    white-space: pre;
}

/* Severity colors */
.severity-high { color: red; font-weight: bold; }
.severity-medium { color: orange; font-weight: bold; }
.severity-low { color: green; }

details summary {
    cursor: pointer;
    font-weight: bold;
    margin-top: 5px;
}
</style>
"""

def _require_panel():
    """Import the optional Panel dependency safely."""
    try:
        import panel as pn
        pn.extension()
        return pn
    except ImportError:
        raise ImportError(
            "Optional dependency 'panel' is not available in this environment "
            "(e.g. WASM/Pyodide). Install it with: pip install panel"
        )


def create_statistics_overview(scanresult):
    """
    Returns a Statistics Overview with Panel
    layout with HTML panes (4 per row).
    """
    pn = _require_panel()  # Panel module is needed for this function
    if not scanresult or not isinstance(scanresult, dict):
        return pn.pane.HTML("⚠️ No scan result")

    statistics = scanresult.get("statistics_overview", {})
    if not statistics:
        return pn.pane.HTML("⚠️ No statistics found")

    title = scanresult.get("package_name", "Unknown")
    version = scanresult.get("package_release", "N/A")

    # Style for statistic cards
    custom_style = {
        "background": "linear-gradient(135deg, #FFF3CC, #FFF9E6)",
        "padding": "16px",
        "min-width": "180px",
        "font-size": "16px",
        "color": "black",
        "border": "none",
        "border-left": "4px solid #E69F00",
        "border-radius": "10px",
    }

    # Style for header (red accent)
    header_style = {
        "background": "#E8F5E9",
        "padding": "16px",
        "min-width": "180px",
        "font-size": "16px",
        "color": "black",
        "border": "none",
        "border-left": "4px solid #4CAF50",
        "border-radius": "10px",
        "margin-bottom": "12px",  # Nice spacing below header
    }

    # Create statistic panes
    panes = []
    for key, value in statistics.items():
        html_content = f"""
            <div style="text-align: center;">
                {key}<br>
                <span style="font-size:22px; font-weight: bold;">{value}</span>
            </div>
        """
        pane = pn.pane.HTML(html_content, styles=custom_style)
        panes.append(pane)

    # Arrange panes: 4 per row
    rows = []
    for i in range(0, len(panes), 4):
        row = pn.Row(*panes[i : i + 4], sizing_mode="stretch_width")
        rows.append(row)

    # Styled Header (full width, matching row width)
    header_html = f"""
        <div>
            Package Overview</br></br>
            <b>{title}</b> — version <b>{version}</b>
        </div>
    """
    header = pn.pane.HTML(header_html, styles=header_style)

    # Final layout: Header + statistic rows
    return pn.Column(header, *rows, sizing_mode="stretch_width")


def report_sast_results(scanresult):
    """
    Generates a complete HTML report of all SAST findings from the scan result.
    Each file's findings are shown in a collapsible <details> element.
    """
    pn = _require_panel()  # Panel module is needed for this function

    # --- Input validation ---
    if not scanresult or not isinstance(scanresult, dict):
        return '<br><h2>⚠️ No scan result provided</h2>'

    file_security_info = scanresult.get("file_security_info")
    if not isinstance(file_security_info, dict) or len(file_security_info) == 0:
        return '<br><h2>⚠️ No file security info found</h2>'

    # Collect files that have SAST results
    files_with_findings = []
    for file_info in file_security_info.values():
        if not isinstance(file_info, dict):
            continue

        sast_result = file_info.get("sast_result")
        if isinstance(sast_result, dict) and len(sast_result) > 0:
            files_with_findings.append(file_info)

    if not files_with_findings:
        return '<br><h2>✅ No security weaknesses found</h2>'

    # --- Safe statistics handling ---
    stats = scanresult.get("statistics_overview")
    if not isinstance(stats, dict):
        stats = {}
    total_number_of_files = stats.get("Number_Of_Files", 1)

    # --- HTML REPORT ---
    html = SAST_REPORT_CSS + f"""
    <div class="sast-report">
        <h2>Detailed Code Security Report</h2>
        <p><strong>Package:</strong> {scanresult.get("package_name", "N/A")}</p>
        <p><strong>version:</strong> {scanresult.get("package_release", "N/A")}</p>
        <p><strong>Total files with findings:</strong> {len(files_with_findings)} of {total_number_of_files} files in total</p>
    """

    for file_info in files_with_findings:
        filename = file_info.get("FileName", "Unknown File")
        sast_result = file_info.get("sast_result", {})

        # --- Normalize findings (fix for list/dict inconsistency) ---
        all_findings = []
        for v in sast_result.values():
            if isinstance(v, dict):
                all_findings.append(v)
            elif isinstance(v, list):
                all_findings.extend([item for item in v if isinstance(item, dict)])

        if not all_findings:
            continue

        num_issues = len(all_findings)

        html += f"""
        <p>⚠️ <b>{num_issues}</b> potential security issue{"s" if num_issues > 1 else ""} 
        found in <b>{filename}</b></p>
        """

        html += "<details>"
        html += "<summary>View identified security weaknesses</summary>"

        html += """
        <table>
            <thead>
                <tr>
                    <th>Line</th>
                    <th>Validation</th>
                    <th>Severity</th>
                    <th>Info</th>
                    <th>Code Snippet</th>
                </tr>
            </thead>
            <tbody>
        """

        # --- Safe sorting ---
        def safe_line(x):
            try:
                return int(x.get("line", 0))
            except (TypeError, ValueError):
                return 0

        sorted_findings = sorted(all_findings, key=safe_line)

        for finding in sorted_findings:
            if not isinstance(finding, dict):
                continue

            line = finding.get("line", "—")
            validation = finding.get("validation", "—")
            severity = finding.get("severity", "—")
            info = finding.get("info", "—")
            code = finding.get("code", "")

            html += f"""
                <tr>
                    <td><strong>{line}</strong></td>
                    <td><code>{validation}</code></td>
                    <td><span class="severity-{severity}">{severity}</span></td>
                    <td>{info}</td>
                    <td>{code}</td>
                </tr>
            """

        html += "</tbody></table>"
        html += "</details><br>"

    html += "</div>"

    RESULT_HTML_PANE = {
        "background": "#FFFFE0",
        "padding": "16px",
        "min-width": "180px",
        "font-size": "16px",
        "color": "black",
        "border": "none",
        "border-left": "4px solid #E69F00",
        "border-radius": "10px",
    }

    return pn.pane.HTML(html, styles=RESULT_HTML_PANE)


def report_used_modules(scanresult):
    """reports used modules for a package"""
    pn = _require_panel()  # Panel module is needed for this function
    # --- Input validation ---
    card1 = ""
    if not scanresult or not isinstance(scanresult, dict):
        return '<br><h2>⚠️ No scan result provided</h2>'
    modules_discovered = scanresult["module_overview"]
    core_modules = modules_discovered["core_modules"]
    external_modules = modules_discovered["imported_modules"]
    card1 += "<details>"
    card1 += "<summary><b>Used Python Standard libraries</b></summary>"

    card1 += (
        "<ul>\n"
        + "\n".join(f"  <li>{module}</li>" for module in core_modules)
        + "\n</ul>"
    )
    card1 += "</details>"

    card2 = "<details>"
    card2 += "<summary><b>Imported libraries (modules)</b></summary>"
    card2 += (
        "<ul>\n"
        + "\n".join(f"  <li>{module}</li>" for module in external_modules)
        + "\n</ul>"
    )
    card2 += "</details>"
    # Style for statistic cards
    custom_style = {
        "background": "linear-gradient(135deg, #FFF3CC, #FFF9E6)",
        "padding": "16px",
        "margin-bottom": "24px",
        "min-width": "180px",
        "font-size": "16px",
        "color": "black",
        "border": "none",
        "border-left": "4px solid #E69F00",
        "border-radius": "10px",
    }
    cardoutput_1 = pn.pane.HTML(card1, styles=custom_style)
    cardoutput_2 = pn.pane.HTML(card2, styles=custom_style)
    cards = pn.Row(cardoutput_1, cardoutput_2)
    return cards


def get_info_text():
    """returns the info text styled
    for the sidebar
    """
    pn = _require_panel()  # Panel module is needed for this function
    custom_style = {
        "background": "linear-gradient(135deg, #F0FDF4, #ECFDF5)",  # soft green tint
        "padding": "18px",
        "min-width": "200px",
        "font-size": "15px",
        "color": "#1F2937",  # slightly richer dark text
        "border": "1px solid #D1FAE5",  # subtle green border
        "border-left": "4px solid #10B981",  # emerald accent
        "border-radius": "12px",
        "box-shadow": "0 2px 6px rgba(0, 0, 0, 0.05)",  # soft depth
    }

    infotext = pn.pane.HTML(
        """
        <p><b>Python Code Audit</b> is a Static Application Security Testing (SAST) tool used to find security weaknesses in Python code.</p>
        <p>Use the CLI version for powerful command-line scanning with many more options.<p>
            <br><br>     
            <a href="https://nocomplexity.com/documents/codeaudit/intro.html"
                target="_blank"
                style="
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    padding: 10px 18px;
                    background-color: #24292f;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: 600;
                    font-size: 15px;
                    transition: all 0.2s ease;
                    width: 200px;
                ">Documentation
                </a>
            <br><br>
            <a href="https://github.com/nocomplexity/codeaudit"
                target="_blank"
                style="
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    padding: 10px 18px;
                    background-color: #24292f;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: 600;
                    font-size: 15px;
                    transition: all 0.2s ease;
                    width: 200px;
                ">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 24 24">
                        <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.66-1.455-3.66-1.455-.495-1.26-1.2-1.59-1.2-1.59-.975-.66.075-.645.075-.645 1.08.075 1.65 1.11 1.65 1.11 0.96 1.635 2.505 1.17 3.12.885.09-.69.375-1.17.675-1.44-2.55-.285-5.22-1.275-5.22-5.67 0-1.26.45-2.28 1.185-3.09-.12-.285-.51-1.425.105-2.97 0 0 .975-.315 3.195 1.185.93-.255 1.92-.375 2.91-.375s1.98.12 2.91.375c2.22-1.5 3.195-1.185 3.195-1.185.615 1.545.225 2.685.105 2.97.735.81 1.185 1.83 1.185 3.09 0 4.41-2.67 5.385-5.22 5.67.405.345.765 1.02.765 2.07 0 1.5-.015 2.715-.015 3.09 0 .315.225.69.825.57C20.565 21.795 24 17.31 24 12c0-6.63-5.37-12-12-12z"/>
                    </svg>
                    GitHub
                </a>
            
            """,
        sizing_mode="stretch_width",
        stylesheets=["""
                .bk-panel {
                    background: transparent !important;
                }
            """],
        styles=custom_style,
    )
    return infotext

def get_disclaimer_text():
    """defines the sidebar disclaimer text"""
    pn = _require_panel()  # Panel module is needed for this function
    
    # Get the version string 
    version_id = __version__
        
    disclaimer = (
        f"<br><b>Disclaimer:</b> This scan only evaluates Python files. "
        f"Security weaknesses can also exist in other files used by a Python package.<br><br>"
        f'This SAST tool <a href="https://github.com/nocomplexity/codeaudit" target="_blank">'
        f"Python Code Audit</a> provides a powerful, automatic security analysis for Python source code. "
        f"However, it's not a substitute for human review in combination with business knowledge. "
        f"Undetected vulnerabilities may still exist."
        f'<p><strong><a href="https://nocomplexity.com/documents/codeaudit/intro.html">Python Code Audit</a></strong> '
        f'Dashboard - version {version_id}</p>'                
    )

    disclaimer_text = pn.pane.HTML(disclaimer)
    return disclaimer_text
