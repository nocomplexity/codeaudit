# SPDX-FileCopyrightText: 2025-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
#
# SPDX-License-Identifier: GPL-3.0-or-later


from pathlib import Path
from codeaudit.api_helpers import _codeaudit_scan_wasm


def test_basic_working_scanning():
    """Checks file name in dict"""
    current_file_directory = Path(__file__).parent

    # validation1.py is in a subfolder:
    validation_file_path = current_file_directory / "validationfiles" / "eval.py"

    result = _codeaudit_scan_wasm(validation_file_path, False)

    # actual_data = find_constructs(source, constructs)
    actual_data = result["file_name"]

    # This is the expected dictionary
    expected_data = "eval.py"  # Assert that the actual data matches the expected data
    assert actual_data == expected_data

def test_scan_wasm1():
    current_file_directory = Path(__file__).parent

    # validation file path
    validation_file_path = current_file_directory / "validationfiles" / "zstd.py"

    result = _codeaudit_scan_wasm(str(validation_file_path), False)
    #Check lines, so the keys:
    lines = result['sast_result']
    line_numbers = set(lines.keys())
    expected_set = {3, 10}

    assert line_numbers == expected_set


def test_scan_wasm1_validationscheck():
    current_file_directory = Path(__file__).parent

    # validation file path
    validation_file_path = current_file_directory / "validationfiles" / "zstd.py"

    result = _codeaudit_scan_wasm(str(validation_file_path), False)
    #Check lines, so the keys:
    lines = result['sast_result']
    validations = [v["validation"] for v in lines.values()]
    expected_set = ['compression.zstd.decompress', 'compression.zstd.open']

    assert validations == expected_set

def test_scan_wasm2():
    current_file_directory = Path(__file__).parent

    # validation file path
    validation_file_path = current_file_directory / "validationfiles" / "eval.py"

    result = _codeaudit_scan_wasm(str(validation_file_path), False)
    actual_data = {int(k): v for k, v in result["sast_result"].items()}

    # Expected dictionary
    expected_data = {
        5: {
            "line": 5,
            "validation": "exec",
            "severity": "High",
            "info": "This function can execute arbitrary code and should be used only with validated constructs.",
            "code": "<pre><code class='language-python'>b = builtins\nb.exec(&quot;2+2&quot;)  # flag 1</code></pre>",
        },
        8: {
            "line": 8,
            "validation": "eval",
            "severity": "High",
            "info": "This function can execute arbitrary code. Never safe with untrusted input.",
            "code": "<pre><code class='language-python'>x = 1\nresult = b.eval(&quot;x + 2&quot;)  # flag 2\nprint(result)  </code></pre>",
        },
        11: {
            "line": 11,
            "validation": "eval",
            "severity": "High",
            "info": "This function can execute arbitrary code. Never safe with untrusted input.",
            "code": "<pre><code class='language-python'>print(eval(&quot;1+1&quot;)) # flag 3\nprint(eval(&quot;os.getcwd()&quot;)) # flag 4</code></pre>",
        },
        12: {
            "line": 12,
            "validation": "eval",
            "severity": "High",
            "info": "This function can execute arbitrary code. Never safe with untrusted input.",
            "code": "<pre><code class='language-python'>print(eval(&quot;1+1&quot;)) # flag 3\nprint(eval(&quot;os.getcwd()&quot;)) # flag 4\nprint(eval(&quot;os.chmod(&#x27;%s&#x27;, 0777)&quot; % &#x27;test.txt&#x27;)) # flag 5</code></pre>",
        },
        13: {
            "line": 13,
            "validation": "eval",
            "severity": "High",
            "info": "This function can execute arbitrary code. Never safe with untrusted input.",
            "code": "<pre><code class='language-python'>print(eval(&quot;os.getcwd()&quot;)) # flag 4\nprint(eval(&quot;os.chmod(&#x27;%s&#x27;, 0777)&quot; % &#x27;test.txt&#x27;)) # flag 5</code></pre>",
        },
        21: {
            "line": 21,
            "validation": "eval",
            "severity": "High",
            "info": "This function can execute arbitrary code. Never safe with untrusted input.",
            "code": "<pre><code class='language-python'>    def foo(self):\n        self.eval()  # flag 6 - but a false flag , but since builtins is imported a known issue! So #nosec</code></pre>",
        },
        23: {
            "line": 23,
            "validation": "eval",
            "severity": "High",
            "info": "This function can execute arbitrary code. Never safe with untrusted input.",
            "code": "<pre><code class='language-python'>Test().eval()  # flag 7 -  due to eval is in contructs list, edge case and hard to solve in a simple way (for now), so marker nosec </code></pre>",
        },
        26: {
            "line": 26,
            "validation": "eval",
            "severity": "High",
            "info": "This function can execute arbitrary code. Never safe with untrusted input.",
            "code": "<pre><code class='language-python'>eval(&quot;os.system(&#x27;rm -rf /&#x27;)&quot;) # flag 8</code></pre>",
        },
        28: {
            "line": 28,
            "validation": "eval",
            "severity": "High",
            "info": "This function can execute arbitrary code. Never safe with untrusted input.",
            "code": "<pre><code class='language-python'>__builtins__.eval(...)  # flag 9  due to eval statement</code></pre>",
        },
        30: [
            {
                "line": 30,
                "validation": "eval",
                "severity": "High",
                "info": "This function can execute arbitrary code. Never safe with untrusted input.",
                "code": "<pre><code class='language-python'>nasty  = __import__(&quot;builtins&quot;).eval     # flag 10 + flag 11  , flag due to __import__  and for eval!</code></pre>",
            },
            {
                "line": 30,
                "validation": "__import__",
                "severity": "Medium",
                "info": "Importing modules dynamically can load untrusted code.",
                "code": "<pre><code class='language-python'>nasty  = __import__(&quot;builtins&quot;).eval     # flag 10 + flag 11  , flag due to __import__  and for eval!</code></pre>",
            },
        ],
    }

    assert actual_data == expected_data
