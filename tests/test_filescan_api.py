# SPDX-FileCopyrightText: 2025-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from pathlib import Path

import tarfile
from codeaudit.api_interfaces import filescan


def test_filescan_single_python_file(monkeypatch, tmp_path):
    test_file = tmp_path / "example.py"
    test_file.write_text("print('hello')\n")

    monkeypatch.setattr(
        "codeaudit.api_interfaces.is_ast_parsable",
        lambda path: True,
    )
    monkeypatch.setattr(
        "codeaudit.api_interfaces.overview_per_file",
        lambda path: {"file_name": "example.py"},
    )
    monkeypatch.setattr(
        "codeaudit.api_interfaces.get_modules",
        lambda path: {"modules": []},
    )
    monkeypatch.setattr(
        "codeaudit.api_interfaces._codeaudit_scan",
        lambda path, nosec_flag=False: {"security_findings": []},
    )

    result = filescan(str(test_file))

    assert result["name"] == "Python_Code_Audit"
    assert "version" in result
    assert "generated_on" in result

    assert "file_security_info" in result
    assert result["file_security_info"]["0"]["file_name"] == "example.py"
    assert result["file_security_info"]["0"]["modules"] == []
    assert result["file_security_info"]["0"]["security_findings"] == []


def test_filescan_python_file_in_tar_gz(monkeypatch, tmp_path):
    tar_path = tmp_path / "example.tar.gz"
    tar_path.write_bytes(b"dummy tar.gz content")

    extracted_dir = tmp_path / "extracted"
    extracted_dir.mkdir()

    python_file = extracted_dir / "example.py"
    python_file.write_text("print('hello')\n")

    class DummyTempHandle:
        def cleanup(self):
            pass

    monkeypatch.setattr(
        "codeaudit.api_interfaces.is_valid_tar_gz",
        lambda path: True,
    )

    monkeypatch.setattr(
        "codeaudit.api_interfaces.get_targz_package_source",
        lambda path: (str(extracted_dir), DummyTempHandle()),
    )

    monkeypatch.setattr(
        "codeaudit.api_interfaces._codeaudit_directory_scan",
        lambda path, nosec_flag=False: {
            "file_security_info": {
                "0": {
                    "file_name": "example.py",
                    "security_findings": [],
                }
            },
            "module_overview": {
                "imported_modules": [],
            },
            "statistics_overview": {
                "External Modules": 0,
            },
        },
    )

    monkeypatch.setattr(
        "codeaudit.api_interfaces.package_imports",
        lambda output: [],
    )

    result = filescan(str(tar_path))

    assert result["name"] == "Python_Code_Audit"
    assert "version" in result
    assert "generated_on" in result

    assert result["package_name"] == "example.tar.gz"

    assert result["file_security_info"]["0"]["file_name"] == "example.py"
    assert result["file_security_info"]["0"]["security_findings"] == []

    assert result["module_overview"]["imported_modules"] == []
    assert result["statistics_overview"]["External Modules"] == 0


def test_filescan_tar_gz():
    current_file_directory = Path(__file__).parent

    validation_file_path = (
        current_file_directory / "validationfiles" / "linkaudit-0.9.9.tar.gz"
    )

    # If filescan() raises any exception, pytest automatically fails.
    result = filescan(validation_file_path)

    assert result is not None
    assert "Error" not in result


@pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning")
def test_filescan_tar_gz_not_exist():
    current_file_directory = Path(__file__).parent

    validation_file_path = (
        current_file_directory / "validationfiles" / "linkaudit-0.9.9.notexist.tar.gz"
    )

    result = filescan(validation_file_path)

    assert "Error" in result
