import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs

def test_hash_strenght():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "hashcheck.py"

    source = read_in_source_file(validation_file_path)
    
    constructs = {'hashlib.md5', 'hashlib.sha1'}
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'hashlib.md5': [19], 
                     'hashlib.sha1': [20,48]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
