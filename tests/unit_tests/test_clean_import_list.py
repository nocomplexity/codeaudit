# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from codeaudit.dashboard_reports import clean_import_list


def test_removes_package_and_submodules():
    modules = [
        "codeaudit",
        "codeaudit.api",
        "codeaudit.reporting",
        "fire",
        "pandas",
    ]

    result = clean_import_list(modules, "codeaudit")

    assert result == ["fire", "pandas"]


def test_removes_private_modules():
    modules = [
        "__about__",
        "_version",
        "altair",
        "codeaudit._private",
        "pyodide.http",
        "package.__init__",
        "package",
    ]

    result = clean_import_list(modules, "codeaudit")

    assert result == ["altair", "pyodide.http", "package"]


def test_keeps_similarly_named_packages():
    modules = [
        "codeaudit2",
        "codeauditor",
        "codeaudit_extra",
        "codeaudit",
        "codeaudit.api",
    ]

    result = clean_import_list(modules, "codeaudit")

    assert result == [
        "codeaudit2",
        "codeauditor",
        "codeaudit_extra",
    ]


def test_empty_module_list():
    assert clean_import_list([], "codeaudit") == []
