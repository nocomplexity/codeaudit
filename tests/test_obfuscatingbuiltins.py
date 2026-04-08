import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs
from codeaudit.security_checks import perform_validations

# constructs are tested in this test file based on SAST checks defined , not  running constructs directly for testing as in other test files.

def test_obfucatedbuiltins_usage():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "obfuscating.py"

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {
        "exec": [6, 17, 22, 37, 43, 44],
        "eval": [8, 12, 47],
        "input": [28, 33, 64],
        "compile": [36],
        "importlib.import_module": [65],
        "__import__": [43, 44, 47, 53, 58],
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
