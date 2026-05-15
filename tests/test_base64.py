# SPDX-FileCopyrightText: 2025-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from pathlib import Path

from codeaudit.security_checks import perform_validations


def test_base64_use():
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "base64.py"

    result = perform_validations(validation_file_path)

    # actual_data = find_constructs(source, constructs)
    actual_data = result["result"]

    # This is the expected dictionary
    expected_data = {
        "base64.b64encode": [9],
        "base64.b64decode": [12, 15],
        "base64.z85decode": [13],
        "exec": [16],
        "base64.b85encode": [13],
    }

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data
