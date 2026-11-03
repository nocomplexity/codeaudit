# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

# This test validates the Python SAST benchmark suite.

import pytest
from pathlib import Path


from codeaudit.api_interfaces import filescan , get_weakness_counts_per_file 

def test_check_benchmark_results():
    current_file_directory = Path(__file__).parent
    # The benchmark files are in a subfolder:
    benchmark_directory = current_file_directory / "benchmarkfiles" / "validpython"     
    result = filescan(benchmark_directory)    
    actual_data = get_weakness_counts_per_file(result)
    
    # This is the expected dictionary - note for testing output!
    expected_data = [{'base_name': 'marshal.py', 'issues': 5},
                    {'base_name': 'vulnerable_parse.py', 'issues': 0},
                    {'base_name': 'obfuscation_example.py', 'issues': 1},
                    {'base_name': 'shelve.py', 'issues': 5},
                    {'base_name': 'xmlrpc.py', 'issues': 2},
                    {'base_name': 'subprocess.py', 'issues': 10},
                    {'base_name': 'os_execution.py', 'issues': 20},
                    {'base_name': 'tarfile_example.py', 'issues': 5},
                    {'base_name': 'input_example.py', 'issues': 2},
                    {'base_name': 'compile.py', 'issues': 1},
                    {'base_name': 'obfuscation_example2.py', 'issues': 2},
                    {'base_name': 'filepermissions.py', 'issues': 8},
                    {'base_name': 'ddos_blockingCPython_example3.py', 'issues': 1},
                    {'base_name': 'logging.py', 'issues': 4},
                    {'base_name': 'tempfile_example.py', 'issues': 1},
                    {'base_name': 'httpserver.py', 'issues': 3},
                    {'base_name': 'forkbomb_example.py', 'issues': 1},
                    {'base_name': 'import_example.py', 'issues': 5},
                    {'base_name': 'syscalls.py', 'issues': 7},
                    {'base_name': 'obfuscation_example3.py', 'issues': 1},
                    {'base_name': 'os_pseudo_fork.py', 'issues': 3},
                    {'base_name': 'exceptionhandling.py', 'issues': 3},
                    {'base_name': 'homoglyphs_example.py', 'issues': 2},
                    {'base_name': 'lzma_open.py', 'issues': 7},
                    {'base_name': 'base64.py', 'issues': 6},
                    {'base_name': 'multiprocessing.py', 'issues': 2},
                    {'base_name': 'zipfile_example.py', 'issues': 15},
                    {'base_name': 'fileoperations.py', 'issues': 3},
                    {'base_name': 'exec_example.py', 'issues': 5},
                    {'base_name': 'osforking.py', 'issues': 1},
                    {'base_name': 'getattr_example.py', 'issues': 1},
                    {'base_name': 'zipfile_example2.py', 'issues': 5},
                    {'base_name': 'ftp.py', 'issues': 2},
                    {'base_name': 'eval_example.py', 'issues': 4},
                    {'base_name': 'sha_examples.py', 'issues': 3},
                    {'base_name': 'os_examples.py', 'issues': 8},
                    {'base_name': 'lzma_example.py', 'issues': 3},
                    {'base_name': 'ddos_blockingCPython_example2.py', 'issues': 1},
                    {'base_name': 'bz2.py', 'issues': 2},
                    {'base_name': 'random.py', 'issues': 9},
                    {'base_name': 'assert.py', 'issues': 1},
                    {'base_name': 'zstd.py', 'issues': 2},
                    {'base_name': 'binding.py', 'issues': 1},
                    {'base_name': 'shutil_example.py', 'issues': 5},
                    {'base_name': 'pickle_example.py', 'issues': 4}]
            

    # Assert that the actual data matches the expected data
    assert actual_data == expected_data