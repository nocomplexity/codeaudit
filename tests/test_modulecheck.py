import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.checkmodules import get_imported_modules

def test_module_check():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "modulecheck.py"
    source = read_in_source_file(validation_file_path)
    
        
    actual_data = get_imported_modules(source) 

    # This is the expected dictionary
    expected_data = {'core_modules': ['csv','os', 'random' ],
                     'imported_modules': ['linkaudit', 'pandas', 'requests']}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
