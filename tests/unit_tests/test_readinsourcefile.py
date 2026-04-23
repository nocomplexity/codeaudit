# SPDX-FileCopyrightText: 2025-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from pathlib import Path
import sys

from codeaudit.filehelpfunctions import read_in_source_file 


def test_read_valid_python_file(tmp_path):
    file = tmp_path / "test.py"
    file.write_text("print('hello')", encoding="utf-8")

    result = read_in_source_file(file)

    assert result == "print('hello')"


def test_reject_directory(tmp_path):
    with pytest.raises(SystemExit) as exc:
        read_in_source_file(tmp_path)

    assert exc.value.code == 1


def test_reject_non_py_file(tmp_path):
    file = tmp_path / "test.txt"
    file.write_text("not python", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        read_in_source_file(file)

    assert exc.value.code == 1


def test_file_read_error(monkeypatch, tmp_path):
    file = tmp_path / "test.py"
    file.write_text("content", encoding="utf-8")

    def mock_open(*args, **kwargs):
        raise IOError("boom")

    monkeypatch.setattr(Path, "open", mock_open)

    with pytest.raises(SystemExit) as exc:
        read_in_source_file(file)

    assert exc.value.code == 1


def test_read_in_source_file_success(tmp_path):
    # Setup: Create a dummy .py file
    test_file = tmp_path / "script.py"
    content = "print('hello world')"
    test_file.write_text(content, encoding="utf-8")

    # Action
    result = read_in_source_file(test_file)

    # Assert
    assert result == content

def test_read_in_source_file_is_directory(tmp_path, capsys):
    # Setup: Use the tmp_path itself (which is a directory)
    with pytest.raises(SystemExit) as excinfo:
        read_in_source_file(tmp_path)

    # Assert
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: The given path is a directory" in captured.out

def test_read_in_source_file_wrong_extension(tmp_path, capsys):
    # Setup: Create a text file instead of .py
    test_file = tmp_path / "notes.txt"
    test_file.write_text("not a python file")

    with pytest.raises(SystemExit) as excinfo:
        read_in_source_file(test_file)

    # Assert
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Error: The given file is not a Python (.py) file" in captured.out

def test_read_in_source_file_not_found(tmp_path, capsys):
    # Setup: A path that doesn't exist
    missing_file = tmp_path / "ghost.py"

    with pytest.raises(SystemExit) as excinfo:
        read_in_source_file(missing_file)

    # Assert
    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert "Failed to read file" in captured.out