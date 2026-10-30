
import sys
import pytest

from codeaudit.api_interfaces import get_weakness_counts


# ---------------------------------------------------------
# Helper for mocking filescan()
# ---------------------------------------------------------

def patch_filescan(monkeypatch, mock_filescan):
    """Patch filescan in the module where get_weakness_counts is defined."""

    module = sys.modules[get_weakness_counts.__module__]

    monkeypatch.setattr(
        module,
        "filescan",
        mock_filescan
    )


# ---------------------------------------------------------
# Test data / fixtures
# ---------------------------------------------------------

@pytest.fixture
def sample_scan_result():
    """Representative scan result containing multiple findings."""

    return {
        "name": "Python_Code_Audit",
        "version": "1.9.2",
        "file_security_info": {
            "0": {
                "FileName": "example.py",
                "sast_result": {
                    "10": {
                        "line": 10,
                        "validation": "os.system",
                        "severity": "High",
                    },
                    "20": {
                        "line": 20,
                        "validation": "pickle.loads",
                        "severity": "High",
                    },
                    "30": [
                        {
                            "line": 30,
                            "validation": "os.system",
                            "severity": "High",
                        },
                        {
                            "line": 30,
                            "validation": "subprocess.call",
                            "severity": "Medium",
                        },
                    ],
                },
            },
            "1": {
                "FileName": "another.py",
                "sast_result": {
                    "15": {
                        "line": 15,
                        "validation": "os.system",
                        "severity": "High",
                    },
                    "25": {
                        "line": 25,
                        "validation": "eval",
                        "severity": "Medium",
                    },
                },
            },
        },
    }


@pytest.fixture
def expected_counts():
    return {
        "os.system": 3,
        "pickle.loads": 1,
        "subprocess.call": 1,
        "eval": 1,
    }


# ---------------------------------------------------------
# 1. Basic interface tests
# ---------------------------------------------------------

def test_returns_dictionary(sample_scan_result):
    result = get_weakness_counts(sample_scan_result)

    assert isinstance(result, dict)


def test_counts_all_weaknesses(sample_scan_result, expected_counts):
    result = get_weakness_counts(sample_scan_result)

    assert result == expected_counts


def test_total_occurrence_count(sample_scan_result):
    result = get_weakness_counts(sample_scan_result)

    assert sum(result.values()) == 6


def test_multiple_findings_in_same_line_are_counted(
    sample_scan_result,
):
    result = get_weakness_counts(sample_scan_result)

    assert result["os.system"] == 3
    assert result["subprocess.call"] == 1


# ---------------------------------------------------------
# 2. File/package scanning interface
# ---------------------------------------------------------

def test_scans_file_path(monkeypatch):

    expected = {"os.system": 2}

    def mock_filescan(input_file, nosec):
        assert input_file == "example.py"
        assert nosec is False

        return {
            "file_security_info": {
                "0": {
                    "sast_result": {
                        "10": {"validation": "os.system"},
                        "20": {"validation": "os.system"},
                    }
                }
            }
        }

    patch_filescan(monkeypatch, mock_filescan)

    result = get_weakness_counts("example.py")

    assert result == expected


def test_scans_package_path(monkeypatch):

    def mock_filescan(input_file, nosec):
        return {
            "file_security_info": {
                "0": {
                    "sast_result": {
                        "10": {
                            "validation": "pickle.loads"
                        }
                    }
                }
            }
        }

    patch_filescan(monkeypatch, mock_filescan)

    result = get_weakness_counts("./my_package")

    assert result == {"pickle.loads": 1}


def test_nosec_parameter_is_forwarded(monkeypatch):

    received = {}

    def mock_filescan(input_file, nosec):
        received["input_file"] = input_file
        received["nosec"] = nosec

        return {"file_security_info": {}}

    patch_filescan(monkeypatch, mock_filescan)

    get_weakness_counts("example.py", nosec=True)

    assert received == {
        "input_file": "example.py",
        "nosec": True,
    }


def test_existing_scan_result_does_not_call_filescan(
    monkeypatch,
    sample_scan_result,
):

    def unexpected_filescan(*args, **kwargs):
        pytest.fail(
            "filescan() should not be called for dictionary input"
        )

    patch_filescan(monkeypatch, unexpected_filescan)

    result = get_weakness_counts(sample_scan_result)

    assert sum(result.values()) == 6


# ---------------------------------------------------------
# 3. Error handling
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "invalid_result",
    [
        None,
        [],
        "invalid",
        123,
        True,
    ],
)
def test_invalid_filescan_result_raises_value_error(
    monkeypatch,
    invalid_result,
):

    patch_filescan(
        monkeypatch,
        lambda *args, **kwargs: invalid_result
    )

    with pytest.raises(ValueError, match="Invalid scan result"):
        get_weakness_counts("example.py")


def test_scanner_error_is_propagated(monkeypatch):

    patch_filescan(
        monkeypatch,
        lambda *args, **kwargs: {
            "Error": "Unable to scan file"
        }
    )

    with pytest.raises(ValueError, match="Unable to scan file"):
        get_weakness_counts("example.py")


# ---------------------------------------------------------
# 4. Missing and empty data
# ---------------------------------------------------------

def test_missing_file_security_info():

    result = get_weakness_counts({})

    assert result == {}


def test_empty_file_security_info():

    result = get_weakness_counts({
        "file_security_info": {}
    })

    assert result == {}


def test_missing_sast_result():

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "FileName": "example.py"
            }
        }
    })

    assert result == {}


def test_empty_sast_result():

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "sast_result": {}
            }
        }
    })

    assert result == {}


# ---------------------------------------------------------
# 5. Malformed input handling
# ---------------------------------------------------------

@pytest.mark.parametrize(
    "file_info",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_invalid_file_info_is_ignored(file_info):

    result = get_weakness_counts({
        "file_security_info": {
            "0": file_info
        }
    })

    assert result == {}


def test_invalid_sast_result_is_ignored():

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "sast_result": "invalid"
            }
        }
    })

    assert result == {}


def test_invalid_findings_are_ignored():

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "sast_result": {
                    "10": None,
                    "20": "invalid",
                    "30": 123,
                    "40": [],
                    "50": [None, "invalid", 123],
                }
            }
        }
    })

    assert result == {}


# ---------------------------------------------------------
# 6. Validation field handling
# ---------------------------------------------------------

def test_missing_validation_uses_unknown():

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "sast_result": {
                    "10": {
                        "line": 10,
                        "severity": "High"
                    }
                }
            }
        }
    })

    assert result == {"Unknown": 1}


@pytest.mark.parametrize(
    "validation",
    [
        None,
        123,
        [],
        {},
        "",
    ],
)
def test_invalid_validation_values_are_ignored(validation):

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "sast_result": {
                    "10": {
                        "validation": validation
                    }
                }
            }
        }
    })

    assert result == {}


def test_multiple_unknown_findings_are_counted():

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "sast_result": {
                    "10": {},
                    "20": {},
                    "30": [
                        {},
                        {},
                    ],
                }
            }
        }
    })

    assert result == {"Unknown": 4}


# ---------------------------------------------------------
# 7. Multiple files and mixed finding structures
# ---------------------------------------------------------

def test_counts_findings_across_multiple_files():

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "sast_result": {
                    "10": {
                        "validation": "os.system"
                    }
                }
            },
            "1": {
                "sast_result": {
                    "20": [
                        {
                            "validation": "os.system"
                        },
                        {
                            "validation": "eval"
                        },
                    ]
                }
            },
            "2": {
                "sast_result": {
                    "30": {
                        "validation": "eval"
                    }
                }
            },
        }
    })

    assert result == {
        "os.system": 2,
        "eval": 2,
    }


def test_mixed_valid_and_invalid_findings():

    result = get_weakness_counts({
        "file_security_info": {
            "0": {
                "sast_result": {
                    "10": {
                        "validation": "os.system"
                    },
                    "20": [
                        {
                            "validation": "eval"
                        },
                        None,
                        "invalid",
                        {
                            "validation": "os.system"
                        },
                    ],
                    "30": None,
                }
            }
        }
    })

    assert result == {
        "os.system": 2,
        "eval": 1,
    }
