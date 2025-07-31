import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs
from codeaudit.security_checks import perform_validations

#constructs are tested in this test file based on SAST checks defined , not  running constructs directly for testing as in other test files.

def test_shelve_usage():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "shelve.py"

        
    #We run now constructs based on definitions!
    # constructs = {'random.random',
    #               'random.seed'}
    
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'shelve.open': [3] ,
                     }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_zipfile_extraction():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "zipfile.py"

            
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'zipfile.ZipFile': [8, 13, 17, 23] ,
                     }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_shutil_constructs():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "shutil.py"

            
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'shutil.unpack_archive': [3],
                      'shutil.copy2': [5, 7],
                        'shutil.copytree': [7],
                          'shutil.chown': [9],
                         'shutil.copy': [13]}
    

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_input_statement():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "inputstatement.py"

            
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'input': [6]}
    

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_marshal_usage():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "marshal.py"

            
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'marshal.loads': [30], 'marshal.load': [36]}
    

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_tar_methods_use():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "tarfilevalidation.py"

            
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'tarfile.TarFile': [6, 10, 17, 22, 24]}
    

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_tempfile_incorrect_use():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "tempcheck.py"

            
    result = perform_validations(validation_file_path)

    #actual_data = find_constructs(source, constructs) 
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'tempfile.mktemp': [3]}
    

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data