import pytest
from pathlib import Path

from codeaudit.security_checks import perform_validations
from codeaudit.suppression import filter_sast_results

def test_suppression_working():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "suppression"  / "sastsuppression_0.py"

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {
        "assert": [46, 47, 48, 75],
        "subprocess.Popen": [15, 16, 18, 19],
        "input": [23, 31],
        "compile": [25, 33],
        "exec": [26, 34, 52, 53, 54, 74],
        "shelve.DbfilenameShelf": [41],
        "gzip.open": [60, 61, 62, 77],
        "os.chmod": [68, 69, 70, 76],
    }

    # Assert that the actual data matches the expected data without suppression
    assert actual_data == expected_data


def test_suppression_suppressedresult():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "suppression"  / "sastsuppression_0.py"

    unfiltered_scan_output = perform_validations(validation_file_path) 
    result = filter_sast_results(unfiltered_scan_output)

    # actual_data = find_constructs(source, constructs)
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {
        "subprocess.Popen": [18, 19],
        "input": [23],
        "compile": [25, 33],
        "exec": [26],
    }

    # Assert that the actual data matches the expected data without suppression
    assert actual_data == expected_data
