import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs

def test_correct_exception_use():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "exception.py"

    source = read_in_source_file(validation_file_path)
    
    constructs = {'pass' ,'continue'}
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'pass': [19] ,
                     'continue': [11]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
