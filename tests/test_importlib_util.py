import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.security_checks import perform_validations


def test_import_util_spec_from_file_use():
    """
    Check to validate correct detection of importlib.util.spec_from_file_location
    """
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "malwareAI.py"

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result["result"]

    # This is the expected dictionary
    expected_data = {
        "importlib.util.module_from_spec": [28, 47],
        "importlib.util.spec_from_file_location": [27, 46],
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
