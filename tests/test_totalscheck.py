import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file

from codeaudit.totals import read_in_source_file , overview_per_file , count_ast_objects

def test_overview_per_file_check():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "correctcounts.py"

    # source = read_in_source_file(validation_file_path)

    actual_data = overview_per_file(validation_file_path) 
    actual_data.pop('FilePath', None)

    # This is the expected dictionary
    expected_data = {
        "FileName": "correctcounts.py",        
        "Number_Of_Lines": 115,
        "AST_Nodes": 57,
        "Std-Modules": 2,
        "External-Modules": 2,
        "Functions": 6,
        "Classes": 0,
        "Comment_Lines": 24,
        "Complexity_Score": 9,
        "warnings": 0,
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_count_ast_objects():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "correctcounts.py"

    source = read_in_source_file(validation_file_path)

    actual_data = count_ast_objects(source)

    # This is the expected dictionary
    expected_data = {
        "AST_Nodes": 57,
        "Std-Modules": 2,
        "External-Modules": 2,
        "Functions": 6,
        "Classes": 0,
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
