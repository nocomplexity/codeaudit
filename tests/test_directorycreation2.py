import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs

def test_os_makedirs():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "directorycreation2.py"
    source = read_in_source_file(validation_file_path)
    constructs = {'os.makedirs'}
        
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'os.makedirs': [10, 79]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_os_mkdir():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "directorycreation2.py"
    source = read_in_source_file(validation_file_path)
    constructs = {'os.mkdir'}
     
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'os.mkdir': [26]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_os_mkfifo():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "directorycreation2.py"
    source = read_in_source_file(validation_file_path)
    constructs = {'os.mkfifo'}
     
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'os.mkfifo': [48]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_os_mknod():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "directorycreation2.py"
    source = read_in_source_file(validation_file_path)
    constructs = {'os.mknod'}
     
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'os.mknod': [65]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_os_makedirs():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "directorycreation2.py"
    source = read_in_source_file(validation_file_path)
    constructs = {'os.makedirs'}
     
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'os.makedirs': [13,82]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_os_makedev():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "directorycreation2.py"
    source = read_in_source_file(validation_file_path)
    constructs = {'os.makedev'}
     
    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'os.makedev': [94]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_sys_calls():
    current_file_directory = Path(__file__).parent
    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "syslibrary.py"
    source = read_in_source_file(validation_file_path)
    constructs = {'sys.call_tracing', 'sys.setprofile', 'sys.settrace'}

    actual_data = find_constructs(source, constructs) 

    # This is the expected dictionary
    expected_data = {'sys.call_tracing': [12], 'sys.setprofile': [29, 31], 'sys.settrace': [35, 37]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
