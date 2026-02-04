import ast
import tokenize
from collections import defaultdict
import re


def get_all_comments_by_line(filename):
    """
    Tokenize the file once and collect all real # comments grouped by starting line.
    
    """
    comments_by_line = defaultdict(list)

    try:
        with tokenize.open(filename) as f:
            tokens = tokenize.generate_tokens(f.readline)
            for token in tokens:
                if token.type == tokenize.COMMENT:
                    text = token.string.lstrip('# \t').rstrip()
                    if text:
                        comments_by_line[token.start[0]].append(text)
    except Exception:
        pass

    return {line: "\n".join(texts) for line, texts in comments_by_line.items()}


def get_start_to_end_lines(filename):
    """
    Parse AST once and build mapping: start_line → highest end_line found for nodes
    starting on that line.
    """
    end_lines = {}

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source = f.read()
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if not hasattr(node, 'lineno'):
                continue
            start = node.lineno
            end = getattr(node, 'end_lineno', start)
            # Take the maximum end line if multiple nodes start on same line
            if start not in end_lines or end > end_lines[start]:
                end_lines[start] = end
    except Exception:
        pass

    return end_lines


def is_suppressed(line, comments_by_line, start_to_end, match_func):
    """
    Check if the statement starting at `line` is suppressed by looking at comments
    from start_line to end_line inclusive.
    """
    end = start_to_end.get(line, line)
    for comment_line in range(line, end + 1):
        comment = comments_by_line.get(comment_line, "")
        if match_func(comment):
            return True
    return False


def filter_sast_results(sast_dict):
    """
    Returns a new filtered dictionary with suppressed findings removed.
    Parses & tokenizes the file only once.
    Respects multi-line statements via AST end_lineno.
    Empty lists and their keys are removed from the result.
    """
    file_location = sast_dict["file_location"]
    original_result = sast_dict.get("result", {})

    if not original_result:
        return sast_dict.copy()

    # Collect all unique line numbers that have findings
    all_issue_lines = set()
    for lines in original_result.values():
        if isinstance(lines, list):
            all_issue_lines.update(lines)

    if not all_issue_lines:
        return sast_dict.copy()

    # Parse and tokenize **once**
    comments_by_line = get_all_comments_by_line(file_location)
    start_to_end = get_start_to_end_lines(file_location)

    # Decide which lines to KEEP
    keep_lines = set()
    for line in sorted(all_issue_lines):
        if not is_suppressed(line, comments_by_line, start_to_end, match_suppression_keyword):
            keep_lines.add(line)

    # Build new result dictionary
    new_result = {}
    for key, value in original_result.items():
        if isinstance(value, list):
            filtered = [ln for ln in value if ln in keep_lines]
            if filtered:
                new_result[key] = filtered
        else:
            new_result[key] = value

    # Return new full dictionary
    filtered_dict = sast_dict.copy()
    filtered_dict["result"] = new_result
    return filtered_dict


def match_suppression_keyword(comment_line):
    """
    Checks if a SAST suppression marker is present in the comment.
    """

    MARKER_LIST = [
        "nosec",
        "nosemgrep",
        "sast-ignore",
        "ignore-sast",
        "security-ignore",
        "ignore-security",
        # False positive / risk handling
        "false-positive",
        "falsepositive",
        "risk-accepted",
        "security-accepted",
        "security-reviewed",
        "security-exception",
    ]

    if not comment_line:
        return False

    normalized = " ".join(
        word.lstrip("#").lower()
        for word in comment_line.split()
    )
    tokens = re.split(r"[^\w\-]+", normalized)
    return any(marker.lower() in tokens for marker in MARKER_LIST)
