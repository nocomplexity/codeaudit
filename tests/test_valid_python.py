# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from pathlib import Path

import ast
import warnings


from codeaudit.filehelpfunctions import is_ast_parsable


class TestIsAstParsable:
    def test_valid_python_file_returns_true(self, tmp_path):
        file_path = tmp_path / "valid.py"
        file_path.write_text(
            "def hello(name):\n" "    return f'Hello, {name}'\n",
            encoding="utf-8",
        )

        assert is_ast_parsable(file_path) is True

    def test_empty_python_file_returns_true(self, tmp_path):
        file_path = tmp_path / "empty.py"
        file_path.write_text("", encoding="utf-8")

        assert is_ast_parsable(file_path) is True

    def test_comments_only_file_returns_true(self, tmp_path):
        file_path = tmp_path / "comments.py"
        file_path.write_text(
            "# This file contains no executable code.\n"
            "# It is still valid Python.\n",
            encoding="utf-8",
        )

        assert is_ast_parsable(file_path) is True

    def test_syntax_error_returns_false(self, tmp_path):
        file_path = tmp_path / "invalid.py"
        file_path.write_text(
            "def broken(:\n" "    pass\n",
            encoding="utf-8",
        )

        assert is_ast_parsable(file_path) is False

    def test_incomplete_python_file_returns_false(self, tmp_path):
        file_path = tmp_path / "incomplete.py"
        file_path.write_text(
            "if True:\n" "    print('missing body continuation'",
            encoding="utf-8",
        )

        assert is_ast_parsable(file_path) is False

    def test_invalid_utf8_returns_false(self, tmp_path):
        file_path = tmp_path / "invalid_encoding.py"
        file_path.write_bytes(b"print('hello')\xff\xfe")

        assert is_ast_parsable(file_path) is False

    def test_null_byte_returns_false(self, tmp_path):
        file_path = tmp_path / "null_byte.py"
        file_path.write_bytes(b"print('hello')\x00")

        assert is_ast_parsable(file_path) is False

    def test_unicode_text_is_supported(self, tmp_path):
        file_path = tmp_path / "unicode.py"
        file_path.write_text(
            "# -*- coding: utf-8 -*-\n" "message = 'こんにちは, café, 🐍'\n",
            encoding="utf-8",
        )

        assert is_ast_parsable(file_path) is True

    def test_syntax_error_with_unicode_source_returns_false(self, tmp_path):
        file_path = tmp_path / "unicode_invalid.py"
        file_path.write_text(
            "# Valid Unicode source\n" "def привет(:\n" "    return '你好'\n",
            encoding="utf-8",
        )

        assert is_ast_parsable(file_path) is False

    def test_missing_file_returns_false(self, tmp_path):
        file_path = tmp_path / "does_not_exist.py"

        assert is_ast_parsable(file_path) is False

    def test_directory_path_returns_false(self, tmp_path):
        assert is_ast_parsable(tmp_path) is False

    def test_non_python_file_returns_false(self, tmp_path):
        file_path = tmp_path / "not_python.txt"
        file_path.write_text(
            "def hello():\n" "    return True\n",
            encoding="utf-8",
        )

        assert is_ast_parsable(file_path) is False


def test_null_byte_file(tmp_path):
    """null byte python file"""
    file_path = tmp_path / "null_byte.py"
    file_path.write_bytes(b"print('hello')\x00")

    assert is_ast_parsable(file_path) is False


def test_null_byte_file2():
    """null byte python file with real file sample"""
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = (
        current_file_directory / "validationfiles" / "incorrect_python_file.py"
    )
    assert is_ast_parsable(validation_file_path) is False
