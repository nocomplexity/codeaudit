import pytest
from pathlib import Path

from codeaudit.security_checks import perform_validations

#constructs are tested in this test file based on SAST checks defined , not  running constructs directly for testing as in other test files.


def test_chmod_constructs():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "chmod_things.py"

            
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'os.access': [5], 'os.chmod': [8, 23, 25]}
    

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data