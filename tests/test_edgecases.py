import pytest
from pathlib import Path

from codeaudit.security_checks import perform_validations


def test_eval():
    """
    11 flags must be found. Changes to the core logic for finding code weakness edge cases often degrade functionality like aliases.

    Note that 

    """
    
    
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "eval.py"

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'exec': [5], 'eval': [8, 11, 12, 13, 21, 23, 26, 28, 30], '__import__': [30]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data


def test_eval2():
    """
    Key for this edge case is to only flag on the assigment - It is a false flag!
    But due to design choices I will not fix it (for now)

    Rationale:
    This is due to the fact that I use a list of constructs, which is easy, extendable etc
    BUT a few edge cases espace. This is one.
    Root cause is in:
        
                elif isinstance(node, ast.Name):
                    resolved = alias_map.get(node.id, node.id)
                    if resolved in constructs_to_detect:
                        construct = resolved
    
    (snippet from core logic file for SAST flagging: issuevalidations.py)
    I will NOT solve this for now, its a edge case that normally will not be seen. Never override built-in variables/ keywords!!! 
    All other edge cases work fine, like aliases etc.

    """
    
    
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "eval2.py"

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result['result']

    # This is the expected dictionary
    expected_data = {'eval': [8]}

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
