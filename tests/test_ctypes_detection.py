# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


import pytest
from pathlib import Path

from codeaudit.security_checks import perform_validations


def test_ctypes_use():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = (
        current_file_directory / "validationfiles" / "ctypes_example.py"
    )

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result["result"]

    # This is the expected dictionary
    expected_data = {'ctypes.cdll.LoadLibrary': [27, 32, 93, 105, 106],
                        'ctypes.windll.LoadLibrary': [110],
                        'ctypes.oledll.LoadLibrary': [113],
                        'ctypes.CDLL': [58, 70, 74, 80],
                        'ctypes.WinDLL': [84],
                        'ctypes.OleDLL': [87]} 
 
    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
