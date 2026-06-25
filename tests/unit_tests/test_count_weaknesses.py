# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

import json

from pathlib import Path

from codeaudit.api_reporting import total_weaknesses


def test_total_weaknesses_counts_all_findings():
    scan_result = {
        "file_security_info": {
            0: {
                "sast_result": {
                    10: {
                        "validation": "assert",
                        "severity": "Low",
                    },
                    20: {
                        "validation": "assert",
                        "severity": "Low",
                    },
                }
            },
            1: {
                "sast_result": {
                    30: {
                        "validation": "eval",
                        "severity": "High",
                    }
                }
            },
            2: {"sast_result": {}},
        }
    }

    assert total_weaknesses(scan_result) == 3


def test_total_weaknesses_empty_scan():
    assert total_weaknesses({}) == 0


def test_total_weaknesses_no_findings():
    scan_result = {
        "file_security_info": {
            0: {"sast_result": {}},
            1: {"sast_result": {}},
        }
    }

    assert total_weaknesses(scan_result) == 0


def test_total_weaknesses_multiple_files():
    scan_result = {
        "file_security_info": {
            0: {
                "sast_result": {
                    1: {"validation": "assert"},
                    2: {"validation": "assert"},
                    3: {"validation": "eval"},
                }
            },
            1: {
                "sast_result": {
                    10: {"validation": "exec"},
                    20: {"validation": "pickle"},
                }
            },
        }
    }

    assert total_weaknesses(scan_result) == 5


def test_total_weaknesses_realoutput_file():
    current_file_directory = Path(__file__).parent

    validation_file_path = (
        current_file_directory.parent / "validationfiles" / "codeaudit_scan.json"
    )
    with open(validation_file_path, encoding="utf-8") as f:
        scan_result = json.load(f)

    assert total_weaknesses(scan_result) == 2
