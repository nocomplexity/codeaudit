import textwrap
import pytest

from codeaudit.suppression import get_all_comments_by_line , match_suppression_keyword

def test_get_all_comments_by_line(tmp_path):
    source = textwrap.dedent(
        """
        # module comment
        #module comment
        x = 1  # inline comment
        y = 2  # first inline  # second inline
        # 
        # trailing comment
        def foo():
            pass  # inside function
        """
    )

    file_path = tmp_path / "example.py"
    file_path.write_text(source)

    result = get_all_comments_by_line(str(file_path))

    assert result == {
        2: "module comment",
        3: "module comment",
        4: "inline comment",
        5: "first inline  # second inline",
        7: "trailing comment",
        9: "inside function",
    }





@pytest.mark.parametrize(
    "comment, expected",
    [
        # --- positive matches (common cases) ---
        ("# nosec", True),
        ("#nosec", True),
        ("# NOSEC", True),
        ("#NOSEC", True),
        ("#   nosec   ", True),
        ("# nosemgrep", True),
        ("# sast-ignore", True),
        ("#sast-ignore", True),
        ("# ignore-sast", True),
        ("# NOSONAR", True),
        ("# security-ignore", True),
        ("# ignore-security", True),

        # --- positive matches (risk handling) ---
        ("# false-positive", True),
        ("# falsepositive", True),
        ("# risk-accepted", True),
        ("# security-reviewed", True),
        ("# security-exception", True),

        # --- inline / mixed content ---
        ("# TODO: fix later  # nosec", True),
        ("Some comment with nosec inside", True),
        ("Reviewed: security-reviewed by team", True),

        # --- negative cases ---
        ("# no security issues found", False),
        ("# ignore this comment", False),
        ("# secure code", False),
        ("just a regular comment", False),
        ("# nosecx", False),          # partial match should not count
        ("# no sec", False),        # partial match should not count
        ("# nosex", False), # this is not funny - AI will not do these things
        ("# false positive", False),  # space breaks the token
        ("# risk accepted", False),

        # --- empty / None ---
        ("", False),
        (None, False),
    ],
)
def test_match_suppression_keyword(comment, expected):
    assert match_suppression_keyword(comment) is expected
