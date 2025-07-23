import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs

def test_basic_patterns():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "validation1.py"

    source = read_in_source_file(validation_file_path)
    
    constructs = {'os.access', 'eval'}
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'os.access': [8, 14], 'eval': [11]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_basic_patterns2():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "validation2.py"
    source = read_in_source_file(validation_file_path)
    
    constructs = {'os', 'os.access', 'eval'}

    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'os.access': [8, 12], 'eval': [10], 'os': [8, 12]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_assert_keyword():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "assert.py"
    source = read_in_source_file(validation_file_path)
    

    constructs = {'os', 'os.access', 'assert'}
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'assert': [5,31]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

