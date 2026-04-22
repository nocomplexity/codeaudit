"""
License GPLv3 or higher.

(C) 2026  @jurgenwigg  

This program is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this
program. If not, see <https://www.gnu.org/licenses/>.

Unit tests for the filehelpfunctions module.
"""

from unittest.mock import patch

from pytest import mark

from codeaudit.filehelpfunctions import collect_python_source_files

_EXCLUDE_DIRS = {"docs", "docker", "dist", "tests"}
_EXAMPLE_DIR = "example_dir"


@mark.xfail(reason="'dirs' in the 'collect_python_source_files' is not used.")
@mark.parametrize("directory", _EXCLUDE_DIRS)
def test_excluded_dirs(directory):
    """Test that excluded directories are not included in the result.

    Test vector:
        - Directory that is excluded from the search.

    Expected behavior:
        - Walk through a directory that is excluded from the search.
        - Verify that the result is an empty list.
    """
    with patch("codeaudit.filehelpfunctions.os", autospec=True) as mocked_os:
        mocked_os.walk.return_value = [(".", [directory], ["example.py"])]
        result = collect_python_source_files(directory=directory)
        assert result == []


def test_not_file():
    """Test that non-file entries are not included in the result.

    Test vector:
        - Directory is not on the excluded list.
        - Tested file is a non-file entry.

    Expected behavior:
        - Walk through a directory with a non-file entry.
        - Verify that the result is an empty list.
    """
    with patch("codeaudit.filehelpfunctions.os", autospec=True) as mocked_os:
        mocked_os.walk.return_value = [(".", [_EXAMPLE_DIR], ["example.py"])]
        mocked_os.path.isfile.return_value = False
        result = collect_python_source_files(directory=_EXAMPLE_DIR)
        assert result == []


def test_not_ast_parsable():
    """Test that non-AST-parsable files are not included in the result.

    Test vector:
        - Directory is not on the excluded list.
        - Tested file exists.
        - Tested file is a non-AST-parsable file.

    Expected behavior:
        - Walk through a directory with a non-AST-parsable file.
        - Verify that the result is an empty list.
    """
    with (
        patch("codeaudit.filehelpfunctions.os", autospec=True) as mocked_os,
        patch(
            "codeaudit.filehelpfunctions.is_ast_parsable", autospec=True
        ) as mocked_is_ast,
    ):
        mocked_os.walk.return_value = [(".", [_EXAMPLE_DIR], ["example.py"])]
        mocked_os.path.isfile.return_value = True
        mocked_is_ast.return_value = False
        result = collect_python_source_files(directory=_EXAMPLE_DIR)
        assert result == []


def test_proper_python_file():
    """Test that proper Python files are included in the result.

    Test vector:
        - Directory is not on the excluded list.
        - Tested file exists.
        - Tested file is a proper Python file.

    Expected behavior:
        - Walk through a directory with a proper Python file.
        - Verify that the result contains the file path.
    """
    with (
        patch("codeaudit.filehelpfunctions.os", autospec=True) as mocked_os,
        patch(
            "codeaudit.filehelpfunctions.is_ast_parsable", autospec=True
        ) as mocked_is_ast,
    ):
        mocked_os.walk.return_value = [(".", [_EXAMPLE_DIR], ["example.py"])]
        mocked_os.path.isfile.return_value = True
        mocked_os.path.abspath.return_value = "./example.py"
        mocked_is_ast.return_value = True
        result = collect_python_source_files(directory=_EXAMPLE_DIR)
        assert result == ["./example.py"]


def test_file_starts_with_dot():
    """Test that files starting with a dot are not included in the result.

    Test vector:
        - Directory is not on the excluded list.
        - Tested file exists.
        - Tested file starts with a dot.

    Expected behavior:
        - Walk through a directory with a file starting with a dot.
        - Verify that the result is an empty list.
    """
    with (
        patch("codeaudit.filehelpfunctions.os", autospec=True) as mocked_os,
        patch(
            "codeaudit.filehelpfunctions.is_ast_parsable", autospec=True
        ) as mocked_is_ast,
    ):
        mocked_os.walk.return_value = [(".", [_EXAMPLE_DIR], [".example.py"])]
        mocked_os.path.isfile.return_value = True
        mocked_is_ast.return_value = False
        result = collect_python_source_files(directory=_EXAMPLE_DIR)
        assert result == []
