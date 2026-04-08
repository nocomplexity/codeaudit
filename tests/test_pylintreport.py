# SPDX-FileCopyrightText: 2025-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
#
# SPDX-License-Identifier: GPL-3.0-or-later

import html

import pandas as pd
import pytest

from codeaudit.reporting import pylint_reporting


def test_basic_functionality():
    result = {
        "file_privacy_check": {
            "file1": {
                "privacy_check_result": [
                    {"lineno": 10, "matched": True, "code": "print('hello')"}
                ]
            }
        }
    }

    df = pylint_reporting(result)

    assert isinstance(df, pd.DataFrame)
    assert list(df.columns) == ["line", "found", "code"]
    assert len(df) == 1

    assert df.loc[0, "line"] == 10
    assert df.loc[0, "found"]


def test_html_escaping():
    code = "<script>alert('x')</script>"
    result = {
        "file_privacy_check": {
            "file1": {
                "privacy_check_result": [{"lineno": 1, "matched": True, "code": code}]
            }
        }
    }

    df = pylint_reporting(result)
    escaped = html.escape(code)

    assert escaped in df.loc[0, "code"]
    assert "<script>" not in df.loc[0, "code"]


def test_newline_conversion():
    code = "a = 1\nb = 2"
    result = {
        "file_privacy_check": {
            "file1": {
                "privacy_check_result": [{"lineno": 2, "matched": False, "code": code}]
            }
        }
    }

    df = pylint_reporting(result)

    assert "<br>" in df.loc[0, "code"]
    assert "a = 1<br>b = 2" in df.loc[0, "code"]


def test_multiple_entries():
    result = {
        "file_privacy_check": {
            "file1": {
                "privacy_check_result": [
                    {"lineno": 1, "matched": True, "code": "x=1"},
                    {"lineno": 2, "matched": False, "code": "y=2"},
                ]
            }
        }
    }

    df = pylint_reporting(result)

    assert len(df) == 2
    assert df["line"].tolist() == [1, 2]


def test_empty_input():
    result = {}

    df = pylint_reporting(result)

    assert df.empty
    assert list(df.columns) == ["line", "found", "code"]


def test_missing_keys():
    result = {
        "file_privacy_check": {
            "file1": {"privacy_check_result": [{}]}  # missing all fields
        }
    }

    df = pylint_reporting(result)

    assert len(df) == 1
    assert pd.isna(df.loc[0, "line"])
    assert pd.isna(df.loc[0, "found"])
    assert "<pre><code" in df.loc[0, "code"]


def test_none_file_privacy_check():
    result = {"file_privacy_check": None}

    df = pylint_reporting(result)

    assert df.empty


def test_no_privacy_results():
    result = {"file_privacy_check": {"file1": {}}}

    df = pylint_reporting(result)

    assert df.empty
