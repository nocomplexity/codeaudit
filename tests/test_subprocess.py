import pytest
from pathlib import Path

from codeaudit.security_checks import perform_validations


def test_subprocess_methods():
    """
    Check if all flags are found
    """

    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "subprocess.py"

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {
        "subprocess.getoutput": [88, 96],
        "subprocess.getstatusoutput": [100],
        "subprocess.run": [20],
        "subprocess.Popen": [44, 63],
        "subprocess.check_call": [79],
        "subprocess.call": [80],
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
