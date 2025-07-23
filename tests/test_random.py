import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs
from codeaudit.security_checks import perform_validations


def test_random_usage():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "random.py"

    source = read_in_source_file(validation_file_path)
    
    # constructs = {'random.random',
    #               'random.seed'}
    
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'random.random': [14] ,
                     'random.seed': [15] }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data