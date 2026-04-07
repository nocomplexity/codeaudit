import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs

def test_os_calls():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "oschecks.py"

    source = read_in_source_file(validation_file_path)
    
    constructs = {
        'os.chmod',
        'os.makedirs',
        'os.mkdir',
        'os.mkfifo',
        'os.mknod',
        'os.makedev',
        'os.fork',
        'os.forkpty'
    }

    
    actual_data = find_constructs(source, constructs) 
    expected_data = {
        'os.chmod': [15],     
        'os.forkpty' :[25],
        'os.fork': [26,32],        
    }


    # This is the expected dictionary
    
    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
