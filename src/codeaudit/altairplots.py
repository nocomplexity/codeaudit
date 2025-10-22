"""
License GPLv3 or higher.

(C) 2025 Created by Maikel Mardjan - https://nocomplexity.com/

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

Altair Plotting functions for codeaudit
"""

import altair as alt
import pandas as pd


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