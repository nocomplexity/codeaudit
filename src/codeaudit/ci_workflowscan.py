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


def ci_scan(input_path, format="text", nosec=True):
    """Basic SAST scan to be used in CI workflows
    The nosec is set to true for CI workflows by default, it can be changed
    Security weakness SHOULD be marked for an exit 0 status in your CI

    Note: If you use JSON output you will have an exit status 0, since you have to determine yourself if there are weaknesses found in your code.
    """
    try:
        scanresult = filescan(input_path, nosec=nosec)
        # collect and return info from scanned files
        if format == "text":
            output, security_status = report_result_txt(scanresult)
        elif format == "json":
            output, security_status = report_result_json(scanresult)
        else:
            # Fallback handling for unsupported formats to prevent output crashes
            output = f"ERROR: Unsupported format '{format}'"
            print(output, file=sys.stderr)
            sys.exit(1)
        print(output)
        if security_status == 0:  # no files with weakness found - or properly marked!
            sys.exit(0)  # correct finish
        else:
            sys.exit(20)  # finish with detected weakness

    except Exception as e:
        # Log the actual error 'e' for debugging CI failures
        print(f"ERROR: Scan failed. Details: {e}", file=sys.stderr)
        sys.exit(1)


def report_result_json(scanresult):
    """Returns scan result in json format.
    Note: not (yet) directly usable since you still need to dive in the dict structure to retrieve results, if any for weaknesses found per file. The resulting json structure is outlined in the documentation. You can use e.g. the `jq` tool. Or join the Python Code Audit community to create CI json output that suites your needs!
    Note that it is hierarchical json structure. See the docs!
    """
    if not isinstance(scanresult, dict):
        raise TypeError("Expected scanresult to be a dictionary")
    file_security_info = scanresult.get("file_security_info")
    files_with_findings_count = 0

    return file_security_info, files_with_findings_count


def report_result_txt(scanresult):
    """Returns scan result in txt format."""
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
