"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

HTML helper functions for codeaudit
"""

import json
from html import escape

def dict_to_html(data):
    """Creates simple HTML from a dict with values that are list:
    Example {'core_modules': ['os', 'hashlib', 'socket', 'logging.config', 'tarfile'],
             'imported_modules': ['linkaudit', 'pandas']}
    """
    html_output = ""

    if not isinstance(data, dict):
        html_output += "<p>None</p>\n"
        return html_output

    for key, items in data.items():
        # Check if items are missing, empty, or not iterable
        if not items or not isinstance(items, (list, tuple)):
            html_output += f"<h3>{key.capitalize()}</h3>\n - not found<ul>\n"
            html_output += "</ul>\n"
            continue

        html_output += f"<h3>{key.capitalize()}</h3>\n<ul>\n"
        try:
            for item in items:
                html_output += f"  <li>{item}</li>\n"
        except Exception:
            html_output += "  <li>None</li>\n"
        html_output += "</ul>\n"

    return html_output


def json_to_html(json_input):
    """
    Takes a Python dictionary or JSON string and returns an HTML page
    that displays the JSON in a formatted and readable way.
    """
    # Parse JSON string if needed
    # Parse if input is a JSON string
    if isinstance(json_input, str):
        json_data = json.loads(json_input)
    else:
        json_data = json_input

    # Pretty-printed JSON string
    pretty_json = json.dumps(json_data, indent=2)

    # Escape HTML characters for safe embedding inside <code>
    escaped_json = escape(pretty_json)

    html_output = f'<div class="json-display">{escaped_json}</div>'
    return html_output


def dict_list_to_html_table(data):
    """
    Converts a list of dictionaries to an HTML table string.
    :param data: List[Dict] - List of dicts with the same keys.
    :return: str - HTML table as string.
    """
    if not data:
        return "<p><em>No data available</em></p>"

    # Get column headers from the first dictionary
    headers = data[0].keys()

    # Start the HTML table
    html = '<table border="1" cellpadding="5" cellspacing="0">\n'
    html += "  <thead>\n    <tr>\n"
    for header in headers:
        html += f"      <th>{header}</th>\n"
    html += "    </tr>\n  </thead>\n  <tbody>\n"

    # Add rows
    for row in data:
        html += "    <tr>\n"
        for header in headers:
            html += f'      <td>{row.get(header, "")}</td>\n'
        html += "    </tr>\n"

    html += "  </tbody>\n</table>"

    return html
