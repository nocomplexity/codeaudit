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
        "Modules",
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
