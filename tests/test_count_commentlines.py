import pytest

from codeaudit.totals import count_comment_lines

def test_single_comment_line():
    source = "# This is a comment\nprint('Hello')"
    result = count_comment_lines(source)
    assert result == {'Comment_Lines': 1}

def test_triple_double_quoted_multiline_string():
    source = '"""\nThis is a docstring\nspanning multiple lines\n"""\nprint("Done")' # I count these as 4 lines. Nocomplexity needed for this tool!
    result = count_comment_lines(source)
    assert result == {'Comment_Lines': 4}

def test_inline_comment_ignored():
    source = "x = 1  # inline comment\n# standalone comment"
    result = count_comment_lines(source)
    assert result == {'Comment_Lines': 1}

def test_single_line_triple_quotes():
    source = '"""This is a single-line docstring"""\nprint("Code")'
    result = count_comment_lines(source)
    assert result == {'Comment_Lines': 1}

def test_mixed_comments_and_docstrings():
    source = '''
# comment 1
"""Docstring line 1
Docstring line 2
"""
x = 5  # inline comment
# comment 2
'''
    result = count_comment_lines(source)
    assert result == {'Comment_Lines': 5}

def test_no_comments_or_docstrings():
    source = "print('Hello')\nx = 2 + 2"
    result = count_comment_lines(source)
    assert result == {'Comment_Lines': 0}
