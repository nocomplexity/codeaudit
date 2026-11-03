# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

# Validation of API function

import pytest
from pathlib import Path

from codeaudit.api_interfaces import get_weakness_counts_per_file


def test_get_weakness_counts_per_file():
    # --- Input with multiple files, various structures ---
    scanresult = {
        "file_security_info": {
            "file1": {
                "FilePath": "src/app/main.py",
                "FileName": "main.py",
                "sast_result": {"issue1": {}, "issue2": {}},
            },
            "file2": {
                "FilePath": "src/utils/helpers.py",
                "FileName": "helpers.py",
                "sast_result": {"issue1": {}},
            },
            "file3": {
                "file_name": "config.py",  # no FilePath -> falls back to file_name
                "sast_result": {"a": {}, "b": {}, "c": {}},
            },
        }
    }

    result = get_weakness_counts_per_file(scanresult)

    expected = [
        {"base_name": "main.py", "issues": 2},
        {"base_name": "helpers.py", "issues": 1},
        {"base_name": "config.py", "issues": 3},
    ]
    assert result == expected


# --- Edge cases: None / invalid input returns None ---

@pytest.mark.parametrize(
    "scanresult",
    [
        {},                                        # missing key
        {"file_security_info": None},              # None value
        {"file_security_info": {}},                # empty dict
        {"file_security_info": "not a dict"},      # wrong type
    ],
)
def test_get_weakness_counts_per_file_returns_none_on_invalid_input(scanresult):
    assert get_weakness_counts_per_file(scanresult) is None


# --- Files without valid sast_result are skipped; if all skipped -> None ---

def test_get_weakness_counts_per_file_skips_invalid_entries():
    scanresult = {
        "file_security_info": {
            "f1": {"FilePath": "a/b.py", "sast_result": {"x": {}}},
            "f2": {"FilePath": "a/c.py"},              # no sast_result -> skip
            "f3": {"FilePath": "a/d.py", "sast_result": "bad"},  # wrong type -> skip
            "f4": "not a dict",                        # wrong type -> skip
        }
    }
    result = get_weakness_counts_per_file(scanresult)
    assert result == [{"base_name": "b.py", "issues": 1}]


def test_get_weakness_counts_per_file_all_invalid_returns_none():
    scanresult = {
        "file_security_info": {
            "f1": {"FilePath": "a/b.py"},  # missing sast_result
            "f2": "not a dict",
        }
    }
    assert get_weakness_counts_per_file(scanresult) is None


# --- Empty sast_result yields 0 issues (a valid, counted record) ---

def test_get_weakness_counts_per_file_empty_sast_result():
    scanresult = {
        "file_security_info": {
            "f1": {"FilePath": "a/clean.py", "FileName": "clean.py", "sast_result": {}},
        }
    }
    result = get_weakness_counts_per_file(scanresult)
    assert result == [{"base_name": "clean.py", "issues": 0}]


# --- base_name fallback: FileName preferred, else filename from path ---

def test_get_weakness_counts_per_file_base_name_fallbacks():
    scanresult = {
        "file_security_info": {
            "f1": {"FilePath": "x/y/zeta.py", "sast_result": {"a": {}}},  # derives from path
            "f2": {"FilePath": "x/y/override.py", "FileName": "given.py",
                   "sast_result": {"a": {}}},                             # explicit FileName wins
        }
    }
    result = get_weakness_counts_per_file(scanresult)
    assert result == [
        {"base_name": "zeta.py", "issues": 1},
        {"base_name": "given.py", "issues": 1},
    ]


def test_get_weakness_counts_per_file2():
    """Black-box tests for crucial input/output behaviour."""

    # 1. Happy path – multiple files with findings
    scanresult = {
        "file_security_info": {
            "file1": {
                "FileName": "app.py",
                "FilePath": "src/app.py",
                "sast_result": {"w1": {}, "w2": {}},          # 2 issues
            },
            "file2": {
                "FileName": "utils.py",
                "FilePath": "src/utils.py",
                "sast_result": {"w1": {}},                     # 1 issue
            },
            "file3": {
                "file_name": "legacy.py",                      # fallback key
                "sast_result": {},                             # 0 issues (still counted)
            },
        }
    }

    result = get_weakness_counts_per_file(scanresult)

    assert isinstance(result, list)
    assert len(result) == 3
    assert {"base_name": "app.py", "issues": 2} in result
    assert {"base_name": "utils.py", "issues": 1} in result
    assert {"base_name": "legacy.py", "issues": 0} in result

    # 2. Missing / empty file_security_info → None
    assert get_weakness_counts_per_file({}) is None
    assert get_weakness_counts_per_file({"file_security_info": {}}) is None
    assert get_weakness_counts_per_file({"file_security_info": None}) is None

    # 3. No valid sast_result entries → None
    scanresult_no_sast = {
        "file_security_info": {
            "file1": {"FileName": "app.py"},                   # no sast_result
            "file2": {"FileName": "utils.py", "sast_result": "invalid"},
        }
    }
    assert get_weakness_counts_per_file(scanresult_no_sast) is None

    # 4. base_name fallback when FileName is missing
    scanresult_fallback = {
        "file_security_info": {
            "file1": {
                "FilePath": "project/src/main.py",
                "sast_result": {"issue": {}},
            }
        }
    }
    result = get_weakness_counts_per_file(scanresult_fallback)
    assert result == [{"base_name": "main.py", "issues": 1}]