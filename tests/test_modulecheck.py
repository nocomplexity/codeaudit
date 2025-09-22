import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.checkmodules import get_imported_modules , check_module_vulnerability

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


def test_module_vulnerability_info():
    ## note: Output can change if more info is added to OSV!

    actual_data = check_module_vulnerability("pandas")

    expected_data = [
        {
            "id": "PYSEC-2020-73",
            "summary": "",
            "details": "** DISPUTED ** pandas through 1.0.3 can unserialize and execute commands from an untrusted file that is passed to the read_pickle() function, if __reduce__ makes an os.system call. NOTE: third parties dispute this issue because the read_pickle() function is documented as unsafe and it is the user's responsibility to use the function in a secure manner.",
            "aliases": ["CVE-2020-13091"],
            "severity": [],
        }
    ]

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
