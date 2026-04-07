import pytest
from pathlib import Path

from codeaudit.filehelpfunctions import read_in_source_file
from codeaudit.issuevalidations import find_constructs
from codeaudit.security_checks import perform_validations


def test_xml_usage():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "xml.py"

    source = read_in_source_file(validation_file_path)

    constructs = {"xmlrpc.client", "xmlrpc.server.SimpleXMLRPCServer"}
    actual_data = find_constructs(source, constructs)

    # This is the expected dictionary
    expected_data = {"xmlrpc.client": [15], "xmlrpc.server.SimpleXMLRPCServer": [8, 28]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_os_interfaces():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "oschecks.py"

    source = read_in_source_file(validation_file_path)

    constructs = {"os.access", "os.write"}
    actual_data = find_constructs(source, constructs)

    # This is the expected dictionary
    expected_data = {"os.access": [6, 12], "os.write": [24]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_base64encoding():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "base64.py"

    source = read_in_source_file(validation_file_path)

    constructs = {"base64"}
    actual_data = find_constructs(source, constructs)

    # This is the expected dictionary
    expected_data = {
        "base64": [3, 4],
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_httpserver_usage():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "httpserver.py"

    source = read_in_source_file(validation_file_path)

    constructs = {"http.server.BaseHTTPRequestHandler", "http.server.HTTPServer"}
    actual_data = find_constructs(source, constructs)

    # This is the expected dictionary
    expected_data = {
        "http.server.BaseHTTPRequestHandler": [5, 26],
        "http.server.HTTPServer": [26],
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_pickle_usage():
    current_file_directory = Path(__file__).parent

    validation_file_path = current_file_directory / "validationfiles" / "pickle.py"

    result = perform_validations(validation_file_path)
    # actual_data = find_constructs(source, constructs)
    actual_data = result["result"]
    # This is the expected dictionary

    expected_data = {
        "pickle.loads": [3, 13],
        "pickle.Unpickler": [17],
        "pickle.load": [8],
    }

    # # Assert that the actual data matches the expected data
    assert actual_data == expected_data
