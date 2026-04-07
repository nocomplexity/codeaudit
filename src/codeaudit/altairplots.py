"""
License GPLv3 or higher.

(C) 2025 - 2026 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

Altair Plotting functions for Python Code Audit (aka codeaudit)
"""

import altair as alt
import pandas as pd

from collections import Counter
from pathlib import Path


def module_count_barchart(scanresult):
    """Create a bar chart showing module counts by category.

    This function generates an Altair bar chart comparing the number of
    Python standard library modules and third-party modules found in the
    provided scan result.

    Args:
        scanresult (dict): Scan result data containing a "module_overview"
            key with "core_modules" and "imported_modules" entries.

    Returns:
        altair.Chart | str: An Altair bar chart visualizing module counts.
        Returns a warning message string if the input is invalid.
    """    
    if not scanresult or not isinstance(scanresult, dict):
        return "⚠️ No scan result available.\n\nPlease run a scan first."
    
    data = scanresult['module_overview']
       
    counts_df = pd.DataFrame({
    'Category': ['Python Standard Libraries', 'Third-party modules'],
    'Count': [len(data['core_modules']), len(data['imported_modules'])]})

    bar_chart = alt.Chart(counts_df).mark_bar(size=60, cornerRadius=8).encode(
        x=alt.X('Category:N', title=None, axis=alt.Axis(labelFontSize=12)),
        y=alt.Y('Count:Q', title='Number of Modules'),
        color=alt.Color('Category:N', 
                        scale=alt.Scale(domain=['Python Standard Libraries', 'Third-party modules'],
                                        range=['#4C78A8', '#F58518'])),
        tooltip=['Category', 'Count']
    ).properties(
        title='Package Modules Overview',
        width=400,
        height=300
    ).configure_title(fontSize=16, anchor='start')

    return bar_chart

def module_distribution_view(scanresult):
    """Create a donut chart showing module distribution.

    Args:
        scanresult (dict): Scan result containing "module_overview" with
            "core_modules" and "imported_modules".

    Returns:
        altair.Chart | str: Donut chart of module distribution, or a warning
        message if input is invalid.
    """
    if not scanresult or not isinstance(scanresult, dict):
        return "⚠️ No scan result available.\n\nPlease run a scan first."

    data = scanresult['module_overview']
    pie_df = pd.DataFrame({
    'Category': ['Python Standard Library modules', 'Imported Libraries'],
    'Count': [len(data['core_modules']), len(data['imported_modules'])],
    'Angle': [len(data['core_modules']), len(data['imported_modules'])]})

    pie_chart = alt.Chart(pie_df).mark_arc(innerRadius=80, outerRadius=140).encode(
        theta=alt.Theta(field="Count", type="quantitative"),
        color=alt.Color('Category:N', 
                        scale=alt.Scale(range=['#4C78A8', '#F58518']),
                        legend=alt.Legend(title="Category")),
        tooltip=['Category', 'Count']
    ).properties(
        title='Module Composition',
        width=380,
        height=380
    )

    # Add percentage text in the center
    text = alt.Chart(pie_df).mark_text(size=16, fontWeight='bold').encode(
        text=alt.Text('Count:Q'),
        color=alt.value('white')
    ).transform_calculate(
        total='datum.Count'
    )

    donut = (pie_chart + text).configure_title(fontSize=16)

    return donut



def make_chart(y_field, df):
    """Function to create a single bar chart with red and grey bars."""

    # Calculate the median (or use any other threshold if needed)
    threshold = df[y_field].median()

    # Add a column for color condition
    df = df.copy()
    df["color"] = df[y_field].apply(lambda val: "red" if val > threshold else "grey")

    chart = (
        alt.Chart(df)
        .mark_bar()
        .encode(
            x=alt.X("FileName:N", sort=None, title="File Name"),
            y=alt.Y(f"{y_field}:Q", title=y_field),
            color=alt.Color(
                "color:N",
                scale=alt.Scale(domain=["red", "grey"], range=["#d62728", "#7f7f7f"]),
                legend=None,
            ),
            tooltip=["FileName", y_field],
        )
        .properties(width=400, height=400, title=y_field)
    )
    return chart


def multi_bar_chart(df):
    """Creates a multi bar chart for all relevant columns"""

    # List of metrics to chart
    metrics = [
        "Number_Of_Lines",
        "AST_Nodes",
        "External-Modules",
        "Functions",
        "Comment_Lines",
        "Complexity_Score",
    ]
    rows = [
        alt.hconcat(*[make_chart(metric, df) for metric in metrics[i : i + 2]])
        for i in range(0, len(metrics), 2)
    ]

    # Stack the rows vertically
    multi_chart = alt.vconcat(*rows)
    return multi_chart



def issue_plot(input_dict):
    """
    Create a radial (polar area) chart using Altair.
    
    Parameters
    ----------
    input_dict : dict
        Dictionary where keys are 'construct' and values are 'count'.
    
    Returns
    -------
    alt.Chart
        Altair chart object.
    """
    # Convert input dict to DataFrame
    df = pd.DataFrame(list(input_dict.items()), columns=['construct', 'count'])

    # Validation
    if not {'construct', 'count'}.issubset(df.columns):
        raise ValueError("DataFrame must have 'construct' and 'count' columns.")

    # Add a combined label for legend
    df["legend_label"] = df["construct"] + " (" + df["count"].astype(str) + ")"

    # Compute fraction of total for angular width
    total = df['count'].sum()
    df['fraction'] = df['count'] / total

    # Compute cumulative angle for start and end of each slice
    df['theta0'] = df['fraction'].cumsum() - df['fraction']
    df['theta1'] = df['fraction'].cumsum()

    # Radial chart using mark_arc
    chart = alt.Chart(df).mark_arc(innerRadius=20).encode(
        theta=alt.Theta('theta1:Q', stack=None, title=None),
        theta2='theta0:Q',  # define start angle
        radius=alt.Radius('count:Q', scale=alt.Scale(type='sqrt')),  # radial extent
        color=alt.Color(
            'legend_label:N',
            scale=alt.Scale(scheme='category20'),
            legend=alt.Legend(title='Weaknesses (Count)')
        ),
        tooltip=['construct', 'count']
    ).properties(
        title='Overview of Security Weaknesses',
        width=600,
        height=600
    )

    return chart


def issue_overview(df):
    """
    Create an Altair arc (donut) chart from a DataFrame 
    with 'call' and 'count' columns, showing counts in the legend.
    """
    # Create a label combining call and count for the legend
    df = df.copy()
    df["label"] = df["call"] + " (" + df["count"].astype(str) + ")"

    chart = (
        alt.Chart(df)
        .mark_arc(innerRadius=50, outerRadius=120)
        .encode(
            theta=alt.Theta("count:Q", title="Count"),
            color=alt.Color("label:N", title="Calls (Count)"),
            tooltip=["call", "count"]
        )
        .properties(
            title="Overview of Security Weaknesses",
            width=600,
            height=600
        )
    )
    return chart


def complexity_heatmap(scanresult):
    """Create an interactive heatmap of file complexity and size.

    Highlights high-risk files based on complexity and lines of code,
    with dynamic filtering and threshold controls.

    Args:
        scanresult (dict): Scan result containing "file_security_info"
            with file-level complexity and size metrics.

    Returns:
        altair.Chart | str: Interactive heatmap chart, or a warning
        message if input is invalid.
    """
    if not scanresult or not isinstance(scanresult, dict):
        return "⚠️ No scan result available.\n\nPlease run a scan first."

    data = scanresult["file_security_info"]
    df = pd.DataFrame([
        {
            "File": f["file_name"],
            "Lines": f["Number_Of_Lines"],
            "Complexity": f["Complexity_Score"],
        }
        for f in data.values()
    ])

    total_files = len(df) # Total number of files (for subtitle)
    df["RiskScore"] = (df["Complexity"] / 80) + (df["Lines"] / 2000)     # define Risk score 
    top_complexity = df.nlargest(30, "Complexity") # Filter for Top 30 by Complexity     
    top_lines = df.nlargest(30, "Lines") # Top 30 by Lines 

    # --- Combine + deduplicate ---
    df_filtered = (
        pd.concat([top_complexity, top_lines])
        .drop_duplicates(subset="File")
        .sort_values("RiskScore", ascending=False)
        .reset_index(drop=True)
    )

    # --- Melt AFTER filtering ---
    df_melted = df_filtered.melt(
        id_vars=["File", "RiskScore"],
        value_vars=["Lines", "Complexity"],
        var_name="Metric",
        value_name="Value"
    )

    # Dynamic slider ranges 
    max_complexity = int(df_filtered["Complexity"].max())
    max_lines = int(df_filtered["Lines"].max())

    complexity_slider = alt.param(
        name="ComplexityThreshold",
        value=int(max_complexity * 0.7),
        bind=alt.binding_range(
            min=0,
            max=max_complexity,
            step=max(1, max_complexity // 100)
        )
    )

    lines_slider = alt.param(
        name="LinesThreshold",
        value=int(max_lines * 0.7),
        bind=alt.binding_range(
            min=0,
            max=max_lines,
            step=max(10, max_lines // 100)
        )
    )

    show_highrisk_only = alt.param(
        name="ShowHighRiskOnly",
        value=False,
        bind=alt.binding_checkbox(name="Show only high-risk files")
    )

    # --- High-risk condition ---
    highrisk_expr = (
        ((alt.datum.Metric == "Complexity") & (alt.datum.Value > complexity_slider)) |
        ((alt.datum.Metric == "Lines") & (alt.datum.Value > lines_slider))
    )

    # --- Filter expression ---
    filter_expr = (~show_highrisk_only) | highrisk_expr

    base = (
        alt.Chart(df_melted)
        .add_params(complexity_slider, lines_slider, show_highrisk_only)
        .transform_filter(filter_expr)
    )

    # Color logic (clean legend restored) ---
    color_scale = alt.condition(
        highrisk_expr,
        alt.value("#ff6b6b"),
        alt.Color(
            "Value:Q",
            scale=alt.Scale(scheme="yellowgreenblue"),
            legend=alt.Legend(title="Value")
        )
    )

    # Heatmap 
    heatmap = base.mark_rect().encode(
        x=alt.X("Metric:N", title="Metric"),
        y=alt.Y(
            "File:N",
            sort=alt.SortField(field="RiskScore", order="descending"),
            title=f"Filtered Files ({len(df_filtered)})"
        ),
        color=color_scale,
        tooltip=[
            "File",
            "Metric",
            "Value",
            alt.Tooltip("RiskScore:Q", format=".2f")
        ]
    ).properties(
        width=500,
        height=450,
        title=alt.TitleParams(
            text="🔥 Code Risk Heatmap",
            subtitle=[
                "Risk heatmap",
                f"Based on {total_files} files"
            ]
        )
    )

    # Text overlay
    text = base.mark_text(size=11).encode(
        x="Metric:N",
        y=alt.Y(
            "File:N",
            sort=alt.SortField(field="RiskScore", order="descending")
        ),
        text=alt.Text("Value:Q", format=".0f"),
        color=alt.condition(
            highrisk_expr,
            alt.value("white"),
            alt.value("black")
        )
    )

    return heatmap + text


def lines_of_code_overview(scanresult, width=800, height=400):
    """Create a bar chart of top files by lines of code.

    Displays the top 30 files ranked by lines of code, with disambiguated
    filenames and tooltips showing full path and complexity.

    Args:
        scanresult (dict): Scan result containing "file_security_info".
        width (int, optional): Chart width in pixels. Defaults to 800.
        height (int, optional): Chart height in pixels. Defaults to 400.

    Returns:
        altair.Chart | str: Bar chart visualization, or a warning
        message if no valid data is available.
    """
    # --- 1. Data Extraction ---
    files_dict = scanresult.get("file_security_info", {})
    if not files_dict:
        return "⚠️ No file data found."

    data = []
    for f in files_dict.values():
        full_path = str(f.get("FilePath", f.get("file_name", "")))
        p = Path(full_path)
        data.append({
            "full_path": full_path,
            "base_name": p.name,
            "parent_folder": p.parent.name if len(p.parts) > 1 else "",
            "lines": f.get("Number_Of_Lines", 0),
            "complexity": f.get("Complexity_Score", 0)
        })
    
    df = pd.DataFrame(data)

    if df.empty:
        return "⚠️ No file info available."

    total_files = len(df)

    # --- 2. Top 30 filter based on lines ---
    df = df.nlargest(30, "lines").sort_values("lines", ascending=False).reset_index(drop=True)

    # --- 3. Smart Labeling: filename + parent folder only if needed ---
    counts = df.groupby("base_name")["base_name"].transform("count")
    df["display_name"] = [
        f"{row['parent_folder']}/{row['base_name']}" if counts.iloc[i] > 1 and row['parent_folder']
        else row['base_name']
        for i, row in df.iterrows()
    ]

    # --- 4. Color scale ---
    color_scale = alt.Scale(scheme="reds", domain=[0, df["lines"].max()])

    # --- 5. Chart ---
    chart = alt.Chart(df).encode(
        y=alt.Y(
            "display_name:N",
            sort=alt.EncodingSortField(field="lines", order="descending"),
            title=f"Top Files ({len(df)})"
        ),
        x=alt.X("lines:Q", title="Lines of Code"),
        tooltip=[
            alt.Tooltip("full_path:N", title="Full Path"),
            alt.Tooltip("lines:Q", title="Lines"),
            alt.Tooltip("complexity:Q", title="Complexity")
        ]
    )

    bars = chart.mark_bar().encode(
        color=alt.Color("lines:Q", scale=color_scale, title="LoC")
    )

    text = chart.mark_text(
        align="left",
        baseline="middle",
        dx=5
    ).encode(
        text=alt.Text("lines:Q", format=",")
    )

    return (bars + text).properties(
        width=width,
        height=height,
        title=alt.TitleParams(
            text="📊 Lines of Code per File",
            subtitle=[f"Top {len(df)} of {total_files} files"]
        )
    ).configure_view(strokeWidth=0)


def ast_nodes_overview(scanresult, width=800, height=400):
    """Create a bar chart of top files by AST node count.

    Displays the top 30 files ranked by AST nodes, with disambiguated
    filenames, derived density metric, and tooltips showing file details.

    Args:
        scanresult (dict): Scan result containing "file_security_info".
        width (int, optional): Chart width in pixels. Defaults to 800.
        height (int, optional): Chart height in pixels. Defaults to 400.

    Returns:
        altair.Chart | str: Bar chart visualization, or a warning
        message if no valid data is available.
    """
    if not scanresult or not isinstance(scanresult, dict):
        return "⚠️ No scan result available.\n\nPlease run a scan first."

    files = scanresult.get("file_security_info", {})
    if not files:
        return "⚠️ No file data found in scan result."

    # Extract data ---
    data = []
    for f in files.values():
        full_path = str(f.get("FilePath", f.get("file_name", "unknown")))
        p = Path(full_path)
        data.append({
            "full_path": full_path,
            "base_name": p.name,
            "parent_folder": p.parent.name if len(p.parts) > 1 else "",
            "ast_nodes": f.get("AST_Nodes", 0),
            "lines": f.get("Number_Of_Lines", 1),  # avoid div by zero
            "complexity": f.get("Complexity_Score", 0),
            "warnings": f.get("warnings", 0)
        })

    df = pd.DataFrame(data)
    if df.empty:
        return "⚠️ No file info available."

    total_files = len(df)

    # Top 30 filter by AST nodes ---
    df = df.nlargest(30, "ast_nodes").sort_values("ast_nodes", ascending=False).reset_index(drop=True)

    # Derived metric ---
    df["ast_density"] = df["ast_nodes"] / df["lines"]

    # Smart Y-axis labels ---
    counts = df.groupby("base_name")["base_name"].transform("count")
    df["display_name"] = [
        f"{row['parent_folder']}/{row['base_name']}" if counts.iloc[i] > 1 and row['parent_folder']
        else row['base_name']
        for i, row in df.iterrows()
    ]
    color_scale = alt.Scale(scheme="reds", domain=[0, df["ast_nodes"].max()])
    threshold = df["ast_nodes"].quantile(0.75)
    rule = alt.Chart(pd.DataFrame({"threshold": [threshold]})).mark_rule(
        color="black",
        strokeDash=[6, 4]
    ).encode(
        x="threshold:Q"
    )
    chart = alt.Chart(df).encode(
        y=alt.Y(
            "display_name:N",
            sort=alt.EncodingSortField(field="ast_nodes", order="descending"),
            title=f"Top Files ({len(df)})"
        ),
        x=alt.X("ast_nodes:Q", title="AST Nodes"),
        tooltip=[
            alt.Tooltip("full_path:N", title="Full Path"),
            alt.Tooltip("ast_nodes:Q", title="AST Nodes"),
            alt.Tooltip("lines:Q", title="Lines"),
            alt.Tooltip("complexity:Q", title="Complexity"),
            alt.Tooltip("ast_density:Q", title="AST Density", format=".2f"),
            alt.Tooltip("warnings:Q", title="Warnings")
        ]
    )
    bars = chart.mark_bar().encode(
        color=alt.condition(
            "datum.warnings > 0",
            alt.value("crimson"),
            alt.Color("ast_nodes:Q", scale=color_scale, title="AST Nodes")
        )
    )   
    text = chart.mark_text(
        align="left",
        baseline="middle",
        dx=5,
        color="black"
    ).encode(
        text=alt.Text("ast_nodes:Q", format=",")
    )
    return (bars + text + rule).properties(
        width=width,
        height=height,
        title=alt.TitleParams(
            text="📊 AST Nodes per File",
            subtitle=[f"Top {len(df)} of {total_files} files"]
        )
    ).configure_view(strokeWidth=0)

def weaknesses_overview(scanresult):
    """Create a bar chart of the most common security weaknesses.

    Aggregates and counts validation findings across all files in the
    scan result, displaying the top occurrences in a bar chart.

    Args:
        scanresult (dict): Scan result containing "file_security_info"
            with SAST validation findings per file.

    Returns:
        altair.Chart: Bar chart of top security weaknesses, or a fallback
        text chart if no data is available.
    """
    if not scanresult or not isinstance(scanresult, dict):
        return alt.Chart(pd.DataFrame({'msg': ['⚠️ No scan result']})).mark_text().encode(text='msg:N')
    
    file_security_info = scanresult.get("file_security_info")
    if not isinstance(file_security_info, dict) or len(file_security_info) == 0:
        return alt.Chart(pd.DataFrame({'msg': ['⚠️ No file security info found']})).mark_text().encode(text='msg:N')

    # --- Count every 'validation' across all files ---
    counter = Counter()
    for file_info in file_security_info.values():
        if not isinstance(file_info, dict):
            continue
        sast_result = file_info.get("sast_result")
        if not isinstance(sast_result, dict):
            continue
        for finding in sast_result.values():
            if isinstance(finding, dict):
                validation = finding.get("validation")
                if validation and isinstance(validation, str):
                    counter[validation] += 1

    if not counter:
        return alt.Chart(pd.DataFrame({'msg': ['✅ No security weaknesses found.']})).mark_text(size=20).encode(text='msg:N')

    # --- Build DataFrame ---
    df = pd.DataFrame(list(counter.items()), columns=["construct", "count"])
    df = df[df["count"] > 0]
    if df.empty:
        return alt.Chart(pd.DataFrame({'msg': ['⚠️ No security weaknesses found']})).mark_text(size=20).encode(text='msg:N')

    # --- Top 50 + formatting ---
    df = df.sort_values("count", ascending=False).head(50).reset_index(drop=True)
    df["construct"] = df["construct"].str.slice(0, 40)
    df["is_top5"] = df.index < 5

    n_constructs = len(df)

    # --- Dynamic sizing ---
    if n_constructs == 1:
        # Single construct → large nice rectangle
        bar_size = 160
        chart_height = 280
        chart_width = 680
    else:
        # Multiple constructs → normal behavior
        bar_size = None
        chart_height = max(380, n_constructs * 22)   # scale height with number of bars
        chart_width = 550

    # --- Bar chart with conditional size ---
    if n_constructs == 1:
        chart = alt.Chart(df).mark_bar(size=bar_size).encode(
            y=alt.Y("construct:N", sort='-x', title=None, axis=alt.Axis(labelLimit=350)),
            x=alt.X("count:Q", title="Number of Occurrences", scale=alt.Scale(type='sqrt')),
            color=alt.Color("count:Q", scale=alt.Scale(scheme="reds"), legend=alt.Legend(title="Count")),
            stroke=alt.condition(alt.datum.is_top5, alt.value("black"), alt.value(None)),
            strokeWidth=alt.condition(alt.datum.is_top5, alt.value(2.5), alt.value(0)),
            tooltip=["construct:N", "count:Q"]
        )
    else:
        chart = alt.Chart(df).mark_bar().encode(
            y=alt.Y("construct:N", sort='-x', title=None, axis=alt.Axis(labelLimit=350)),
            x=alt.X("count:Q", title="Number of Occurrences", scale=alt.Scale(type='sqrt')),
            color=alt.Color("count:Q", scale=alt.Scale(scheme="reds"), legend=alt.Legend(title="Count")),
            stroke=alt.condition(alt.datum.is_top5, alt.value("black"), alt.value(None)),
            strokeWidth=alt.condition(alt.datum.is_top5, alt.value(2.5), alt.value(0)),
            tooltip=["construct:N", "count:Q"]
        )

    # --- Labels on bars ---
    text = alt.Chart(df).mark_text(
        align='left',
        dx=5,
        fontSize=11,
        color='black'
    ).encode(
        y=alt.Y("construct:N", sort='-x'),
        x="count:Q",
        text="count:Q"
    )

    # --- Final chart ---
    final_chart = (chart + text).properties(
        title=alt.TitleParams(
            text="Top Security Weaknesses (by Validation)",
            anchor="start",
            fontSize=15
        ),
        width=chart_width,
        height=chart_height,
        padding={"left": 10, "right": 35, "top": 15, "bottom": 10}
    ).configure_view(stroke=None).configure_axis(
        grid=False,
        labelFontSize=12,
        titleFontSize=13
    )

    return final_chart

def sast_files_overview(scanresult):
    """Create a bar chart of security issues per file.

    Aggregates SAST findings across files and visualizes the number of
    security issues per file. Filenames are disambiguated using the
    parent folder when duplicates exist.

    Args:
        scanresult (dict): Scan result containing "file_security_info"
            with per-file SAST findings and metadata.

    Returns:
        altair.Chart: Bar chart of files with security issues, or a
        fallback text chart if no valid data is available.
    """    
    if not isinstance(scanresult, dict) or not scanresult:
        return alt.Chart(pd.DataFrame({'msg': ['⚠️ No scan result']}))\
            .mark_text(size=20).encode(text='msg:N')

    file_security_info = scanresult.get("file_security_info")
    if not isinstance(file_security_info, dict) or not file_security_info:
        return alt.Chart(pd.DataFrame({'msg': ['⚠️ No file security info found']}))\
            .mark_text().encode(text='msg:N')
    
    records = []
    for file_info in file_security_info.values():
        if not isinstance(file_info, dict):
            continue

        sast_result = file_info.get("sast_result")
        if not isinstance(sast_result, dict) or not sast_result:
            continue

        filepath = file_info.get("FilePath") or file_info.get("file_name", "")
        path_obj = Path(str(filepath))

        base_name = file_info.get("FileName") or path_obj.name or "Unknown"
        parent_folder = path_obj.parent.name if len(path_obj.parts) > 1 else None
        if parent_folder in ("", ".", "/"):
            parent_folder = None

        records.append({
            "base_name": base_name,
            "parent_folder": parent_folder,
            "full_path": str(filepath),
            "issues": len(sast_result),
            "complexity": file_info.get("Complexity_Score", 0),
        })

    if not records:
        return alt.Chart(pd.DataFrame({
            'msg': ['✅ No security weaknesses identified.']
        })).mark_text(size=14).encode(text='msg:N')

    df = pd.DataFrame(records)

    # --- Smart labeling for duplicates ---
    name_counts = df.groupby("base_name")["base_name"].transform("count")
    df["display_name"] = [
        f"{row.parent_folder}/{row.base_name}"
        if name_counts.iloc[i] > 1 and row.parent_folder
        else row.base_name
        for i, row in df.iterrows()
    ]

    # --- Sort by issue count ---
    df = df.sort_values("issues", ascending=False).reset_index(drop=True)

    # --- Chart ---
    base_chart = alt.Chart(df).encode(
        y=alt.Y(
            "display_name:N",
            sort='-x',
            title=None,
            axis=alt.Axis(labelLimit=420, labelFontSize=12)
        ),
        x=alt.X(
            "issues:Q",
            title="Number of Security Issues",
            axis=alt.Axis(tickMinStep=1)
        ),
        color=alt.Color(
            "issues:Q",
            scale=alt.Scale(scheme="orangered"),
            legend=alt.Legend(title="Issues")
        ),
        tooltip=[
            alt.Tooltip("display_name:N", title="File"),
            alt.Tooltip("issues:Q", title="Security Issues"),
            alt.Tooltip("complexity:Q", title="Complexity Score"),
            alt.Tooltip("full_path:N", title="Full Path"),
        ]
    )

    bars = base_chart.mark_bar(cornerRadiusEnd=6, size=22)

    labels = base_chart.mark_text(
        align="left",
        baseline="middle",
        dx=8,
        fontSize=12,
        fontWeight="bold"
    ).encode(text="issues:Q")

    chart = (bars + labels).properties(
        title=alt.TitleParams(
            text=f"Files with Security Issues — {scanresult.get('package_name', 'Unknown Package')}",
            subtitle=f"Total files with findings: {len(df)}",
            anchor="start",
            fontSize=16,
            subtitleFontSize=12
        ),
        width=720,
        height=max(340, len(df) * 28)
    ).configure_view(stroke=None).configure_axis(
        grid=True,
        gridColor="#f0f0f0",
        labelFontSize=12,
        titleFontSize=13
    )

    return chart



def weaknesses_radial_overview(scanresult):
    """
    Returns a radial (polar area) chart showing the number of times each 'validation'
    appears across all files in the full scan result.
    """   
    # --- Input validation ---
    if not scanresult or not isinstance(scanresult, dict):
        return alt.Chart(pd.DataFrame({'msg': ['⚠️ No scan result']})).mark_text().encode(text='msg:N')
    
    file_security_info = scanresult.get("file_security_info")
    if not isinstance(file_security_info, dict) or len(file_security_info) == 0:
        return alt.Chart(pd.DataFrame({'msg': ['⚠️ No file security info found']})).mark_text().encode(text='msg:N')

    # --- Count every 'validation' across all files ---
    counter = Counter()
    for file_info in file_security_info.values():
        if not isinstance(file_info, dict):
            continue
        sast_result = file_info.get("sast_result")
        if not isinstance(sast_result, dict):
            continue
        for finding in sast_result.values():
            if isinstance(finding, dict):
                validation = finding.get("validation")
                if validation and isinstance(validation, str):
                    counter[validation] += 1

    if not counter:
        return alt.Chart(pd.DataFrame({'msg': ['✅ No security weaknesses found. No radial chart created.']})).mark_text(size=14).encode(text='msg:N')

    # --- Build DataFrame ---
    df = pd.DataFrame(list(counter.items()), columns=["construct", "count"])
    df = df[df["count"] > 0]
    if df.empty:
        return alt.Chart(pd.DataFrame({'msg': ['✅ No security weaknesses found. No radial chart created.']})).mark_text(size=14).encode(text='msg:N')

    # --- Top 50 + formatting ---
    df = df.sort_values("count", ascending=False).head(50).reset_index(drop=True)
    df["construct"] = df["construct"].str.slice(0, 40)
    df["legend_label"] = df["construct"] + " (" + df["count"].astype(str) + ")"

    # --- Compute fractions and angles for polar area chart ---
    total = df['count'].sum()
    df['fraction'] = df['count'] / total

    if len(df) == 1:
        # Only one construct → full circle
        df['theta0'] = 0
        df['theta1'] = 1
        inner_radius = 120           # larger inner radius for single construct
        radius_scale = alt.Scale(type='sqrt', zero=True, domain=[0, df['count'].max() * 1.2])
    else:
        df['theta0'] = df['fraction'].cumsum() - df['fraction']
        df['theta1'] = df['fraction'].cumsum()
        inner_radius = 20
        radius_scale = alt.Scale(type='sqrt', zero=True)

    # --- Radial chart ---
    chart = alt.Chart(df).mark_arc(innerRadius=inner_radius).encode(
        theta=alt.Theta('theta1:Q', stack=None, title=None),
        theta2='theta0:Q',
        radius=alt.Radius('count:Q', scale=radius_scale),
        color=alt.Color(
            'legend_label:N',
            scale=alt.Scale(scheme='category20'),
            legend=alt.Legend(title='Weaknesses (Count)')
        ),
        tooltip=['construct:N', 'count:Q']
    ).properties(
        title='Overview of Security Weaknesses',
        width=600,
        height=600
    )

    return chart
