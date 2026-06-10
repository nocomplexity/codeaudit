"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan and all contributors - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.


Functionality to use Python Code Audit within CI workflows.
"""

import sys
import json
from codeaudit.api_interfaces import filescan
from codeaudit.dashboard_reports import SAST_REPORT_CSS

PYTHON_CODE_AUDIT_TEXT = '<a href="https://github.com/nocomplexity/codeaudit" target="_blank"><b>Python Code Audit</b></a>'
DISCLAIMER_TEXT = (
    '<div class="sast-report"><p><b>Disclaimer:</b> <i>This SAST tool '
    + PYTHON_CODE_AUDIT_TEXT
    + " provides a powerful, automatic security analysis for Python source code. However, it's not a substitute for human review in combination with business knowledge. Undetected vulnerabilities may still exist.</i></p></div>"
)
FOOTER_TEXT = (
    '<div class="sast-report"><p>Check the <a href="https://nocomplexity.com/documents/codeaudit/intro.html" '
    'target="_blank">documentation</a> for help on found issues.<br></p></div>'
)

NOSEC_WARNING = '<div class="sast-report"><p><b>INFO</b>: The --nosec flag is active. Security findings with in-line suppressions will be excluded from the report.</p></div>'


def ci_scan(input_path, output="text", nosec=True):
    """Run a SAST scan for CI workflows.

    Args:
        input_path: Path to the file or directory to scan.
        output: Report format ("text", "html", or "json").
        nosec: Whether to ignore findings marked with ``# nosec``.

    Exits:
        0: No reportable weaknesses found and used always for JSON output
        3: Weaknesses found.
        1: Scan error or invalid output format.
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

        # Exit codes:
        #   0 = clean (no weaknesses or properly marked with nosec)
        #   3 = weaknesses found (allowed in CI via allow_failure: true)
        if security_status == 0:
            sys.exit(0)  # clean finish
        else:
            sys.exit(3)  # weaknesses found → job "failed" but pipeline continues

    except Exception as e:
        # Log the actual error for debugging CI failures
        print(f"ERROR: Scan failed. Details: {e}", file=sys.stderr)
        sys.exit(1)


def safe_line(x):
    """Safe sorting helper function"""
    try:
        return int(x.get("line", 0))
    except (TypeError, ValueError):
        return 0


def report_result_txt(scanresult):
    """Generate a human-readable text report for CI mode scan results.

    Args:
        scanresult: Dictionary returned by the scan engine.

    Returns:
        Tuple[str, int]: Report text and number of files with findings.
    """
    # Ensure scanresult is a dictionary to prevent crash on .get()
    if not isinstance(scanresult, dict):
        print("❌ Error: Invalid scan result data format structure.", file=sys.stderr)
        return "", 0

    file_security_info = scanresult.get("file_security_info")
    if not isinstance(file_security_info, dict) or len(file_security_info) == 0:
        print("⚠️ Warning: No file security info found!", file=sys.stderr)
        return "", 0

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

    # Gather sast results that are relevant for CI output
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
    html += DISCLAIMER_TEXT + FOOTER_TEXT
    return html, 1


def report_result_json(scanresult):
    """Returns scan result in JSON output format as tuple (json_string, files_with_findings_count).
    By design no codesnippet is returned in this json output.
    """
    # Ensure scanresult is a dictionary to prevent crash on .get()
    if not isinstance(scanresult, dict):
        print("❌ Error: Invalid scan result data format structure.", file=sys.stderr)
        error_json = json.dumps(
            {"error": True, "message": "Invalid scan result data format structure."}
        )
        return error_json, 0

    file_security_info = scanresult.get("file_security_info")
    if not isinstance(file_security_info, dict) or len(file_security_info) == 0:
        print("⚠️ Warning: No file security info found!", file=sys.stderr)
        warning_json = json.dumps(
            {"warning": True, "message": "No file security info found!"}
        )
        return warning_json, 0

    # Prepare data structure for JSON output
    files_data = []
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
        file_scan_location = file_info.get("FilePath", "Unknown")

        sorted_findings = sorted(all_findings, key=safe_line)

        # Format findings for this file
        findings_list = []
        for finding in sorted_findings:
            if not isinstance(finding, dict):
                continue

            finding_entry = {
                "line": finding.get("line", "—"),
                "weakness": finding.get("validation", "—"),
                "severity": finding.get("severity", "—"),
                "info": finding.get("info", "—"),
            }
            findings_list.append(finding_entry)

        # Add file data
        file_data = {
            "filename": filename,
            "file_location": file_scan_location,
            "num_issues": len(all_findings),
            "findings": findings_list,
        }
        files_data.append(file_data)

    # Gather stats
    stats = scanresult.get("statistics_overview")
    if not isinstance(stats, dict):
        stats = {}
    total_number_of_files = stats.get("Number_Of_Files", 1)

    # Build the output structure
    output_data = {
        "files_data": files_data,
        "total_files_with_findings": files_with_findings_count,
        "total_files_checked": total_number_of_files,
    }

    # Build the summary structure
    if files_with_findings_count == 0:
        summary_data = {
            "status": "clean",
            "message": "✅ No security issue(s) found in file(s) or Package.",
            "total_files_with_findings": files_with_findings_count,
            "total_files_checked": total_number_of_files,
        }
        summary_json = json.dumps(summary_data, indent=2)
        return summary_json, files_with_findings_count
    else:
        # For consistency, include the summary in the output data
        output_data["summary"] = (
            f"Total files with findings: {files_with_findings_count} of {total_number_of_files} Python files checked."
        )
        output_json = json.dumps(output_data, indent=2)
        return output_json, files_with_findings_count
