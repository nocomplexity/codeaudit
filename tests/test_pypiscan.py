import pytest

from codeaudit.pypi_package_scan import get_pypi_download_info

#Note This testfunction does NOT make real API calls to PyPI! So check if testdata is still correct in cause of errors.

from unittest.mock import patch

@pytest.fixture
def mock_pypi_response():
    """Provides a template for a successful PyPI API response."""
    return {
        "info": {"version": "1.2.3"},
        "releases": {
            "1.2.3": [
                {
                    "packagetype": "bdist_wheel",
                    "url": "https://files.pythonhosted.org/package-1.2.3-py3-none-any.whl"
                },
                {
                    "packagetype": "sdist",
                    "url": "https://files.pythonhosted.org/package-1.2.3.tar.gz"
                }
            ]
        }
    }

@patch('codeaudit.pypi_package_scan.get_pypi_package_info')
def test_get_pypi_download_info_success(mock_get, mock_pypi_response):
    """Test successful retrieval of sdist URL."""
    mock_get.return_value = mock_pypi_response
    
    result = get_pypi_download_info("some-package")
    
    assert result["release"] == "1.2.3"
    assert result["download_url"] == "https://files.pythonhosted.org/package-1.2.3.tar.gz"

@patch('codeaudit.pypi_package_scan.get_pypi_package_info')
def test_get_pypi_download_info_no_package(mock_get):
    """Test behavior when the package does not exist (returns False)."""
    mock_get.return_value = False
    
    result = get_pypi_download_info("non-existent-package")
    
    assert result is False

@patch('codeaudit.pypi_package_scan.get_pypi_package_info')
def test_get_pypi_download_info_no_sdist(mock_get, mock_pypi_response):
    """Test when the version exists but no sdist (.tar.gz) is available."""
    # Remove the sdist entry from the mock data
    mock_pypi_response["releases"]["1.2.3"] = [
        {"packagetype": "bdist_wheel", "url": "https://files...whl"}
    ]
    mock_get.return_value = mock_pypi_response
    
    result = get_pypi_download_info("some-package")
    
    assert result["release"] == "1.2.3"
    assert result["download_url"] is None

@patch('codeaudit.pypi_package_scan.get_pypi_package_info')
def test_get_pypi_download_info_wrong_extension(mock_get, mock_pypi_response):
    """Test when an sdist exists but is not a .tar.gz file."""
    mock_pypi_response["releases"]["1.2.3"][1]["url"] = "https://files...source.zip"
    mock_get.return_value = mock_pypi_response
    
    result = get_pypi_download_info("some-package")
    
    assert result["download_url"] is None
