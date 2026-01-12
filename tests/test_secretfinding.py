import pytest
from pathlib import Path

from codeaudit.privacy_lint import secret_scan , count_privacy_check_results

def test_secretfinding():
    current_file_directory = Path(__file__).parent

    # apivalidations.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "apivalidations.py"
    real_secrets_found = secret_scan(validation_file_path)
    
    actual_number_found = count_privacy_check_results(real_secrets_found)
    expected_number = 22  #secrets are exact match with words in the secretslist!


    # This is the expected dictionary
    
    # Assert that the actual data matches the expected data
    assert actual_number_found == expected_number
