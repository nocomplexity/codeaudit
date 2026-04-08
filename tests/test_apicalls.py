import pytest
from pathlib import Path

from codeaudit.api_interfaces import version , get_overview

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.checkmodules import get_imported_modules 


def test_api_version():    
            
    actual_data = version()
    assert "name" in actual_data
    assert "version" in actual_data
    assert actual_data["name"] == "Python_Code_Audit"
    # just check version format, not exact number
    assert isinstance(actual_data["version"], str)
    assert actual_data["version"].count(".") >= 1  # Test valid for all version, unless API has major change


def test_get_overview_errorfile():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "dunderexec_with_parsing_error.py" #This file can NOT be parsed
    #source = read_in_source_file(validation_file_path)
            
    actual_data = get_overview(validation_file_path) 

    # This is the expected dictionary
    expected_data = {'Error': 'File is not a *.py file, does not exist or is not a valid directory path to a Python package.'}
    
    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_get_overview_validfile():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "obfuscating.py"
    # source = read_in_source_file(validation_file_path)

    actual_data = get_overview(validation_file_path) 
    del actual_data["FilePath"] #not interested in FilePath for testing.

    # This is the expected dictionary - note for testing output!
    expected_data = {
        "FileName": "obfuscating.py",        
        "Number_Of_Lines": 54,
        "AST_Nodes": 32,
        "Std-Modules": 2,
        "External-Modules": 0,
        "Functions": 0,
        "Classes": 0,
        "Comment_Lines": 5,
        "Complexity_Score": 1,
        "warnings": 0,
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
