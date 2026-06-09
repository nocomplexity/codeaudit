"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan and all contributors - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.


Functionality to use Python Code Audit within CI workflows.
"""

import sys
from codeaudit.api_interfaces import filescan
from codeaudit.dashboard_reports import SAST_REPORT_CSS

# PYTHON_CODE_AUDIT_TEXT = '<a href="https://github.com/nocomplexity/codeaudit" target="_blank"><b>Python Code Audit</b></a>'
# DISCLAIMER_TEXT = (
#     '<div class="sast-report"><p><b>Disclaimer:</b> <i>This SAST tool '
#     + PYTHON_CODE_AUDIT_TEXT
#     + " provides a powerful, automatic security analysis for Python source code. However, it's not a substitute for human review in combination with business knowledge. Undetected vulnerabilities may still exist.</i></p></div>"
# )

NOSEC_WARNING = '<div class="sast-report"><p><b>INFO</b>: The --nosec flag is active. Security findings with in-line suppressions will be excluded from the report.</p></div>'

# HTML_FOOTER = (
#     '<div class="sast-report"><p><hr>'
#     + 'Check the <a href="https://nocomplexity.com/documents/codeaudit/intro.html" '
#     + 'target="_blank">documentation</a> for help on found issues.<br>'
#     + "</p></div>"
# )


def ci_scan(input_path, output="text", nosec=True):
    """Basic SAST scan to be used in CI workflows
    The nosec is set to true for CI workflows by default, it can be changed
    Security weakness SHOULD be marked for an exit 0 status in your CI

    Note: If you use JSON output you will have an exit status 0, since you have to determine yourself if there are weaknesses found in your code.

    Set an options in your CI job like e.g. allow_failure:True since jobs that run can result in detecting weaknesses and this is no failure of the job!
    """
    try:
        scanresult = filescan(input_path, nosec=nosec)
        # collect and return info from scanned files
        if output == "text":
            result, security_status = report_result_txt(scanresult)
            print(result)
        elif output == "html":
            result, security_status = report_result_html(scanresult)
            if nosec:
                result = NOSEC_WARNING + result
            print(result)
        elif output == "json":
            result, security_status = report_result_json(scanresult)
            print(result)
        else:
            # Fallback handling for unsupported formats to prevent output crashes
            result = f"ERROR: Unsupported format '{output}'"
            print(result, file=sys.stderr)
            sys.exit(1)
        if security_status == 0:  # no files with weakness found - or properly marked!
            sys.exit(0)  # correct finish
        else:
            sys.exit(3)  # finish with detected weakness
    except Exception as e:
        # Log the actual error 'e' for debugging CI failures
        print(f"ERROR: Scan failed. Details: {e}", file=sys.stderr)
        sys.exit(1)


def report_result_json(scanresult):
    """Returns scan result in json outputformat.
    Note: not (yet) directly usable since you still need to dive in the dict structure to retrieve results, if any for weaknesses found per file. The resulting json structure is outlined in the documentation. You can use e.g. the `jq` tool. Or join the Python Code Audit community to create CI json output that suites your needs!
    Note that it is hierarchical json structure. See the docs!
    """
    if not isinstance(scanresult, dict):
        raise TypeError("Expected scanresult to be a dictionary")
    file_security_info = scanresult.get("file_security_info")
    files_with_findings_count = 0

    return file_security_info, files_with_findings_count


def report_result_txt(scanresult):
    """Returns scan result in txt output format."""
    # Ensure scanresult is a dictionary to prevent crash on .get()
    if not isinstance(scanresult, dict):
        print("❌ Error: Invalid scan result data format structure.", file=sys.stderr)
        return ""

    file_security_info = scanresult.get("file_security_info")
    if not isinstance(file_security_info, dict) or len(file_security_info) == 0:
        print("⚠️ Warning: No file security info found!", file=sys.stderr)
        return ""

    output = ""
    files_with_findings_count = 0

    for file_info in file_security_info.values():
        if not isinstance(file_info, dict):
            continue

        sast_result = file_info.get("sast_result")
        if not isinstance(sast_result, dict) or len(sast_result) == 0:
            continue

        # --- Normalize findings ---
        all_findings = []
        for v in sast_result.values():
            if isinstance(v, dict):
                all_findings.append(v)
            elif isinstance(v, list):
                all_findings.extend([item for item in v if isinstance(item, dict)])

        if not all_findings:
            continue

        # If we made it here, this file actually has valid findings
        files_with_findings_count += 1
        filename = file_info.get("FileName", "Unknown File")
        num_issues = len(all_findings)

        output += f"\n⚠️ {num_issues} potential security issue{'s' if num_issues > 1 else ''} found in {filename}\n"
        file_scan_location = file_info.get("FilePath", "Unknown")
        output += f"File location: {file_scan_location} \n"

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

            output += (
                f"line:{line}\tweakness: {validation}\tseverity:{severity}->{info}\n"
            )

    # Gather stats
    stats = scanresult.get("statistics_overview")
    if not isinstance(stats, dict):
        stats = {}
    total_number_of_files = stats.get("Number_Of_Files", 1)

    if files_with_findings_count == 0:
        summary = "✅ No security issue(s) found in file(s) or Package.\n"
    else:
        summary = ""

    summary += f"\nTotal files with findings: {files_with_findings_count} of {total_number_of_files} Python files checked."

    if files_with_findings_count == 0:
        return summary, files_with_findings_count
    else:
        return output + summary, files_with_findings_count


def report_result_html(scanresult):
    """HTML output - as artifact"""
    # --- Input validation ---
    if not scanresult or not isinstance(scanresult, dict):
        return "<br><h2>⚠️ No scan result provided</h2>", 1

    file_security_info = scanresult.get("file_security_info")
    if not isinstance(file_security_info, dict) or len(file_security_info) == 0:
        return "<br><h2>⚠️ No file security info found</h2>", 1

    # Collect files that have SAST results
    files_with_findings = []
    for file_info in file_security_info.values():
        if not isinstance(file_info, dict):
            continue

        sast_result = file_info.get("sast_result")
        if isinstance(sast_result, dict) and len(sast_result) > 0:
            files_with_findings.append(file_info)

    if not files_with_findings:
        html = "<br><h2>✅ No security weaknesses found</h2>"
        return html, 0

    # --- Safe statistics handling ---
    stats = scanresult.get("statistics_overview")
    if not isinstance(stats, dict):
        stats = {}
    total_number_of_files = stats.get("Number_Of_Files", 1)

    # --- HTML REPORT ---
    html = SAST_REPORT_CSS + f"""
    <div class="sast-report">
        <h2>Code Security Scan Results</h2>
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
    # html += DISCLAIMER_TEXT
    # html += HTML_FOOTER

    return html, 1
