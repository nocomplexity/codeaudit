"""
License GPLv3 or higher.

(C) 2026 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

API functions: Helpers for SAST Benchmark suite
"""
from pathlib import Path
import re
import ast
import pandas as pd
import panel as pn
from codeaudit.api_interfaces import filescan , get_weakness_counts_per_file
from codeaudit.filehelpfunctions import collect_python_source_files


def get_project_root():
    current = Path(__file__).resolve()
    # Walk up the directory tree looking for project markers
    for parent in [current, *current.parents]:
        if (parent / "pyproject.toml").exists() and (parent / "tests").exists():
            return parent
    raise FileNotFoundError("Could not find project root.")

# Build the path dynamically
PROJECT_ROOT = get_project_root()
BENCHMARK_FILES = PROJECT_ROOT / "tests" / "benchmarkfiles" / "validpython"

import ast
from pathlib import Path


def extract_sast_meta(source):
    """
    Extract the top-level SAST_META dictionary from a Python file or source string.

    Args:
        source: A file path (str or Path) or Python source code string.

    Returns:
        The SAST_META value as a Python dict, or None if not found / invalid.
    """
    if isinstance(source, (str, Path)):
        try:
            path = Path(source)
        except (ValueError, TypeError) as exc:
            # Input cannot be a path (e.g. null byte in string, wrong type).
            # This is expected for source-code strings, so stay quiet-ish,
            # but still report the reason instead of swallowing it.
            print(f"extract_sast_meta: not a valid path ({type(exc).__name__}: {exc})")
        else:
            try:
                if path.is_file():
                    source = path.read_text(encoding="utf-8")
            except ValueError as exc:
                # e.g. embedded null byte in the path.
                print(
                    f"extract_sast_meta: invalid path "
                    f"({type(exc).__name__}: {exc}); treating as source"
                )
            except OSError as exc:
                # Permissions, broken symlink, I/O error, etc.
                print(
                    f"extract_sast_meta: could not read file "
                    f"({type(exc).__name__}: {exc.strerror or 'I/O error'}); "
                    f"falling back to treating input as source"
                )

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None

    for node in tree.body:
        value_node = None

        # Normal assignment: SAST_META = {...}
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SAST_META":
                    value_node = node.value
                    break

        # Annotated assignment: SAST_META: dict = {...}
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id == "SAST_META"
                and node.value is not None
            ):
                value_node = node.value

        if value_node is not None:
            try:
                data = ast.literal_eval(value_node)
            except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
                return None
            return data if isinstance(data, dict) else None

    return None


def create_sast_meta_overview(directory):
    """Creates a list which contains the SAST_META data of all files in a directory
    
    Returns:
        list[dict]: A list of dictionaries, one per Python source file found.
        
    """
    files_to_check = collect_python_source_files(directory)
    all_sast_info = []
    file_info = {}
    for file in files_to_check:
        file_name = Path(file).name
        file_info = { "filename" :file_name } | extract_sast_meta(file) 
        all_sast_info.append(file_info)
    return all_sast_info


def create_issues_with_titles(issues_data, titles_data):
    """
    Create a list of dicts containing filename, weaknesses, and title.
    
    Args:
        issues_data: list of dicts with 'base_name' and 'weaknesses'
        titles_data: list of dicts with 'filename' and 'title' (plus other fields)
    
    Returns:
        list of dicts: [{'filename': ..., 'weaknesses': ..., 'title': ...}, ...]
    """
    # Build a lookup from filename -> title
    title_lookup = {item['filename']: item['title'] for item in titles_data}
    
    result = []
    for item in issues_data:
        filename = item['base_name']
        result.append({
            'filename': filename,            
            'title': title_lookup.get(filename) , # None if no matching title found
            'weaknesses': item['issues'],
        })
    
    return result

def benchmark_overview_issues_per_file(benchmark_files=BENCHMARK_FILES):
    """Creates a overview of weaknesses per benchmark file"""    
    benchmark_results = filescan(benchmark_files)
    benchmark_list = get_weakness_counts_per_file(benchmark_results)
    titles = create_sast_meta_overview(benchmark_files)
    overview = create_issues_with_titles(benchmark_list , titles)
    df = pd.DataFrame(overview)
    df = df.sort_values(by='filename').reset_index(drop=True)
    formatters = {                        
            "title":       {"type": "textarea"},
        }

    table = pn.widgets.Tabulator(
        df,
        header_filters=False,
        show_index=False,
        formatters=formatters,
        pagination="local",
        page_size=50,
        layout='fit_columns',
        selectable=True,
        theme="semantic-ui",        
        # --- fixed column width ---
        widths={'weaknesses': 150 ,
                'title': 350,
                'filename': 200},         # pixels
    )   
    return table

def cwe_to_html(cwe_value, column_name="cwe_id"):
    """
    Convert a CWE value (single int, or list of ints) into an HTML clickable string.
    Each CWE number N becomes <a href="https://cwe.mitre.org/data/definitions/N.html">N</a>.
    Lists are rendered as comma-separated clickable links.
    Empty / NaN values are returned unchanged (as empty string).
    """
    if cwe_value is None:
        return ""

    # Handle NaN (float) safely.  pd.isna raises TypeError/ValueError for
    # array-like inputs (lists, tuples, sets), which we handle explicitly
    # below — so those are expected.  Anything else is reported rather than
    # silently swallowed.
    try:
        if pd.isna(cwe_value):
            return ""
    except (TypeError, ValueError) as exc:
        # Only report if the input isn't one of the shapes we already know
        # how to handle; otherwise list inputs would print on every row.
        if not isinstance(cwe_value, (list, tuple, set)):
            print(
                f"cwe_to_html[{column_name}]: pd.isna() failed unexpectedly "
                f"({type(exc).__name__}: {exc})"
            )

    def make_link(n):
        n = str(n).strip()
        if not n.isdigit():
            print(
                f"cwe_to_html[{column_name}]: refusing non-numeric CWE value {n!r}"
            )
            return ""
        return (
            f'<a href="https://cwe.mitre.org/data/definitions/{n}.html" '
            f'target="_blank">{n}</a>'
        )

    # List / tuple / set of CWEs
    if isinstance(cwe_value, (list, tuple, set)):
        return ", ".join(make_link(n) for n in cwe_value)

    # Single value (int, numpy int, or string)
    return make_link(cwe_value)



def owasp_to_html(value):
    """
    Convert an OWASP Top 10 string like "A04:2021 - Insecure Design"
    or "A02:2025 - Security Misconfiguration" into an HTML clickable link.

    URL pattern:
        https://top10.owasp.org/{year}/{Axx}_{year}-{Name_With_Underscores}/
    """
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError) as e:
        print(f"Warning: Could not evaluate pd.isna() on value due to {e}. Continuing.")

    if value is None:
        return ""
    text = str(value).strip()

    # Match "A04:2021 - Insecure Design" / "A02:2025 - Security Misconfiguration"
    match = re.match(
        r"^\s*(A\d{2})\s*:\s*(\d{4})\s*[-–—]\s*(.+?)\s*$",
        text,
        flags=re.IGNORECASE,
    )
    if not match:
        # Return original text unchanged if it doesn't match the expected format
        return text

    category, year, name = match.groups()
    category = category.upper()
    year = year.strip()
    name = name.strip()

    # Convert "Security Misconfiguration" -> "Security_Misconfiguration"
    # Collapse whitespace to single underscores
    name_slug = re.sub(r"\s+", "_", name)

    url = f"https://top10.owasp.org/{year}/{category}_{year}-{name_slug}/"

    return f'<a href="{url}" target="_blank">{text}</a>'


def transform_owasp_column(df, column="owasp", inplace=False):
    """
    Apply owasp_to_html to every value in the specified column.
    """
    if not inplace:
        df = df.copy()
    df[column] = df[column].apply(owasp_to_html)
    return df


def transform_cwe_column(df, column="cwe_id", inplace=False):
    """
    Apply cwe_to_html to every value in the given column of a DataFrame.
    """
    if not inplace:
        df = df.copy()
    df[column] = df[column].apply(cwe_to_html)
    return df

def benchmark_suite_overview(benchmarklist=BENCHMARK_FILES):
    """Creates a Tabulator to display the benchmark suite collection of Python files
    These files contain SAST meta information
    
    input: benchmarklist , type list
    """    
    benchmarklist = create_sast_meta_overview(BENCHMARK_FILES)
    df = pd.DataFrame(benchmarklist)

    df = transform_cwe_column(df)
    df = transform_owasp_column(df) #transform owasp column    
    df = df[['filename', 'title', 'cwe_id', 'weakness', 'owasp', 'severity']].copy()    

    formatters = {
        "cwe_id": {"type": "html", "field": "html"},
        "owasp":   {"type": "html", "field": "html"},
        "title":       {"type": "textarea"},
        "weakness":       {"type": "textarea"},
        "tags":       {"type": "textarea"},
    }
    table = pn.widgets.Tabulator(
    df,
    header_filters=False,
    show_index=False, 
    formatters=formatters,
    pagination="local",
    page_size=50,
    layout='fit_columns',        
    selectable=True,
    theme="simple",
    sizing_mode='stretch_width',  # Add this line
    )
    
    return table


