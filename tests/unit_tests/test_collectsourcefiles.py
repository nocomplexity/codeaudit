# SPDX-FileCopyrightText: 2025-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Validation on correct behaviour of collect_python_source_files function.

"""
import pytest
import os
from pathlib import Path

from codeaudit.filehelpfunctions import collect_python_source_files  

def test_underscore_file_inclusion(tmp_path):
    """
    Verifies that files starting with underscores (like __init__.py) 
    are INCLUDED in the current os.walk implementation.
    """
    # 1. Setup: Create a mix of files
    (tmp_path / "normal.py").write_text("x = 1")
    (tmp_path / "_private.py").write_text("x = 2")
    (tmp_path / "__init__.py").write_text("# init file")
    (tmp_path / ".hidden.py").write_text("x = 3")  # Should be skipped

    # 2. Action
    results = collect_python_source_files(str(tmp_path))
    
    # Convert results to filenames for easy comparison
    found_filenames = [os.path.basename(p) for p in results]

    # 3. Assertions
    assert "normal.py" in found_filenames
    assert "_private.py" in found_filenames    # This confirms the current Version 2 logic
    assert "__init__.py" in found_filenames    # This confirms the current Version 2 logic
    assert ".hidden.py" not in found_filenames  # This confirms dot-files are skipped

def test_collect_skips_invalid_ast(tmp_path, capsys):
    # 1. Create one valid file and one invalid file
    valid_file = tmp_path / "good.py"
    valid_file.write_text("x = 10")
    
    invalid_file = tmp_path / "bad.py"
    invalid_file.write_text("this is definitely not python syntax :::")

    results = collect_python_source_files(str(tmp_path))
    
    assert any("good.py" in r for r in results)
    
    # The invalid file should NOT be there
    assert not any("bad.py" in r for r in results)
    
    # Verify the error message was printed to the console
    captured = capsys.readouterr()
    assert "skipped due to syntax error" in captured.out


def test_collect_python_files_full_logic(tmp_path):
    """
    Tests the three main behaviors of collect_python_source_files:
    1. It skips excluded directories (tests, docs, etc.)
    2. It skips hidden files (starting with '.')
    3. It filters out files that are not AST parsable.
    """
        
    valid_file = tmp_path / "main.py"
    valid_file.write_text("def hello(): print('world')", encoding="utf-8")
    
    underscore_file = tmp_path / "__init__.py"
    underscore_file.write_text("# package init", encoding="utf-8")

    # File in an EXCLUDED directory (Should be skipped)
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()
    excluded_file = docs_dir / "setup.py"
    excluded_file.write_text("print('skip me')", encoding="utf-8")

    # Hidden file (Should be skipped by default exclude filter)
    hidden_file = tmp_path / ".config.py"
    hidden_file.write_text("secret = True", encoding="utf-8")

    # Invalid Python file (AST Syntax Error - Should be skipped)
    invalid_file = tmp_path / "broken.py"
    invalid_file.write_text("if True: \n    print('Missing closing parenthesis'", encoding="utf-8")
    
    results = collect_python_source_files(str(tmp_path))        
    found_filenames = [os.path.basename(p) for p in results]
    
    assert "main.py" in found_filenames
    assert "__init__.py" in found_filenames
    
    # These should be filtered out
    assert "setup.py" not in found_filenames      # Directory excluded
    assert ".config.py" not in found_filenames    # Hidden file
    assert "broken.py" not in found_filenames     # AST Parse error
    
    # Ensure we got exactly 2 files
    assert len(found_filenames) == 2