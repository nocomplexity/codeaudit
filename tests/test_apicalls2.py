# SPDX-FileCopyrightText: 2025-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
#
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest

from codeaudit.api_interfaces import _generation_info



def test_generation_info_simple():
    result = _generation_info()
    
    # Check that the constant 'name' is correct
    assert result["name"] == "Python_Code_Audit"
    
    # Check that all required keys are present
    assert "version" in result
    assert "generated_on" in result
    
    # Verify the output has exactly 3 items
    assert len(result) == 3
    