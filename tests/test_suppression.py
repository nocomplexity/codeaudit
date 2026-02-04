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
        "assert": [43, 44, 45, 80],
        "subprocess.Popen": [16, 17, 21, 22],
        "input": [25, 31],
        "compile": [27, 33],
        "exec": [28, 34, 49, 50, 51, 79],
        "shelve.DbfilenameShelf": [38],
        "gzip.open": [59, 60, 61, 82],
        "os.chmod": [70, 71, 72, 81],
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
        "subprocess.Popen": [21, 22],
        "input": [25],
        "compile": [27, 33],
        "exec": [28],
    }

    # Assert that the actual data matches the expected data without suppression
    assert actual_data == expected_data
