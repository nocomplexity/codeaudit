# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

# This test validates the Python SAST benchmark suite.

from pathlib import Path

from codeaudit.api_interfaces import filescan, get_weakness_counts_per_file


# Expected number of issues per benchmark file.
# NOTE: This is the expected test output - keep in sync with benchmarkfiles/validpython.
EXPECTED_ISSUES = {'marshal.py': 5,
 'vulnerable_parse.py': 0,
 'obfuscation_example.py': 1,
 'shelve.py': 5,
 'xmlrpc.py': 2,
 'subprocess.py': 10,
 'os_execution.py': 20,
 'tarfile_example.py': 5,
 'input_example.py': 2,
 'compile.py': 1,
 'obfuscation_example2.py': 2,
 'filepermissions.py': 8,
 'assert_check.py': 1,
 'ddos_blockingCPython_example3.py': 1,
 'logging.py': 4,
 'tempfile_example.py': 1,
 'httpserver.py': 3,
 'forkbomb_example.py': 1,
 'import_example.py': 5,
 'syscalls.py': 7,
 'obfuscation_example3.py': 1,
 'os_pseudo_fork.py': 3,
 'exceptionhandling.py': 3,
 'homoglyphs_example.py': 2,
 'lzma_open.py': 7,
 'base64.py': 6,
 'multiprocessing.py': 2,
 'zipfile_example.py': 15,
 'fileoperations.py': 3,
 'exec_example.py': 5,
 'log4shell_pattern.py': 3,
 'osforking.py': 1,
 'getattr_example.py': 1,
 'zipfile_example2.py': 5,
 'ftp.py': 2,
 'eval_example.py': 4,
 'sha_examples.py': 3,
 'os_examples.py': 8,
 'lzma_example.py': 3,
 'ddos_blockingCPython_example2.py': 1,
 'bz2.py': 2,
 'random.py': 9,
 'assert.py': 1,
 'zstd.py': 2,
 'binding.py': 1,
 'shutil_example.py': 5,
 'pickle_example.py': 4}



def test_check_benchmark_results():
    current_file_directory = Path(__file__).parent
    # The benchmark files are in a subfolder:
    benchmark_directory = current_file_directory / "benchmarkfiles" / "validpython"

    result = filescan(benchmark_directory)
    actual_data = get_weakness_counts_per_file(result)

    # Convert the (possibly unordered) list of results into a dict keyed by file name.
    # This makes the comparison independent of file ordering, which can vary per system.
    actual_issues = {entry["base_name"]: entry["issues"] for entry in actual_data}

    # Sanity check: no duplicate base_names in the result (would silently hide errors).
    assert len(actual_issues) == len(actual_data), (
        f"Duplicate base_names found in scan results: {[e['base_name'] for e in actual_data]}"
    )

    # Compare the sets of files first, so a mismatch gives a clear, focused message.
    expected_files = set(EXPECTED_ISSUES)
    actual_files = set(actual_issues)
    missing = expected_files - actual_files
    unexpected = actual_files - expected_files
    assert not missing, f"Benchmark files missing from scan results: {sorted(missing)}"
    assert not unexpected, f"Unexpected benchmark files in scan results: {sorted(unexpected)}"

    # Now compare issue counts per file (order-independent).
    assert actual_issues == EXPECTED_ISSUES

