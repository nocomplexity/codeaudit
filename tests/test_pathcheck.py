import pytest
from pathlib import Path


from codeaudit.security_checks import perform_validations

def test_path_open_use():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "path.py"

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {
        "pathlib.Path.read_text": [23],
        "pathlib.Path.read_bytes": [28],
        "pathlib.Path.open": [11, 15, 20],
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
