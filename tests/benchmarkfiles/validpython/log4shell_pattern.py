"""
Portions of this file are derived from the Taint Analysis Masterclass,
originally licensed under the MIT License:

    Copyright (c) 2025 Taint Analysis Masterclass Contributors

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
---

Modifications Copyright (c) 2026 Maikel Mardjan(https://nocomplexity.com/)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Log4Shell Pattern: Expression/Template Injection

================================================================================
CVE Information
================================================================================
CVE ID:        CVE-2021-44228 (Log4Shell)
Product:       Apache Log4j 2.x (Java)
Severity:      CRITICAL (CVSS 10.0)
CWE:           CWE-917 (Expression Language Injection)
               CWE-502 (Deserialization of Untrusted Data)
Published:     2021-12-10

Description:
    Apache Log4j2 2.0-beta9 through 2.14.1 JNDI features do not protect against
    attacker-controlled LDAP and other JNDI related endpoints.

    While Log4Shell is a Java vulnerability, this file demonstrates the
    EQUIVALENT PATTERN in Python: logging user input that gets interpreted
    as an expression/template rather than literal text.

References:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228
    - https://logging.apache.org/log4j/2.x/security.html
    - https://www.lunasec.io/docs/blog/log4j-zero-day/

================================================================================
Pattern Analysis
================================================================================
The Log4Shell vulnerability pattern involves:
1. User-controlled data reaching a logging function
2. The logging system interpreting special syntax (${...}) as expressions
3. Expression evaluation leading to JNDI lookup → Remote code loading

Python equivalents:
- Template injection in logging format strings
- eval/exec in log processing
- SSTI when logs are rendered in templates

Log4Shell Pattern Detection Requirements:

Key Lesson from Log4Shell:
  Never interpret user data as code/expressions/templates.
  Data should remain data, not become part of the control flow.

================================================================================
"""
# sast_meta data
SAST_META = {
    "title": "Arbitrary Code Execution and Format/Template Injection via User-Controlled Logging",
    "cwe_id": [94, 95, 134],  # 94 Improper Control of Generation of Code ('Code Injection'), 95 Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection'), 134 Improper Neutralization of Format Strings
    "weakness": "Improper Control of Generation of Code ('Code Injection')",
    "owasp": "A05:2025 - Injection",
    "severity": "Critical",
    "cvss": 9.8,
    "impact": "Critical",
    "tags": [
        "eval",
        "code-injection",
        "eval-injection",
        "format-string",
        "template-injection",
        "ssti",
        "logging",
        "log4shell-analog",
        "user-input",
        "arbitrary-code-execution",
        "rce",
        "python",
        "jinja2",
        "string-template"
    ],
}


import logging
import string

# Configure logging for demonstration
logger = logging.getLogger(__name__)


# ==============================================================================
# VULNERABLE PATTERNS (Python Equivalents)
# ==============================================================================

def vulnerable_format_string_logging(request):
    """
    VULNERABLE: User input in format string (Python equivalent of Log4Shell pattern)

    While Python's logging doesn't have JNDI, format string vulnerabilities
    can leak sensitive information or cause DoS.

    This pattern is analogous to Log4Shell where user data is interpreted
    as part of the log format.

    Payload example:
        username = "%(password)s"  # Could leak if password is in scope
    """
    username = request.GET.get('username', '')  # SOURCE: UserControlled

    # VULN: User input as part of format string
    # In Python, this can leak local variables if using % formatting
    logger.info("Login attempt for: %s" % username)  # Safer but still logged

    # More dangerous variant with .format()
    log_message = "User {username} logged in".format(username=username)
    logger.info(log_message)

    # CRITICAL: If log_template is user-controlled (like Log4j's message lookup)
    log_template = request.GET.get('log_format', 'User: {username}')  # SOURCE
    try:
        formatted = log_template.format(username=username)  # SINK: Format injection
        logger.info(formatted)
    except (KeyError, ValueError):
        pass

    return {'status': 'logged'}


def vulnerable_template_logging(request):
    """
    VULNERABLE: String.Template with user input (Another Python analog)

    Python's string.Template uses ${var} syntax similar to Log4j's lookups.
    While it doesn't do remote lookups, the pattern similarity is notable.
    """
    from string import Template

    user_message = request.POST.get('message', '')  # SOURCE: UserControlled

    # VULN: User-controlled template string
    template_str = request.POST.get('template', 'Message: $message')  # SOURCE

    try:
        template = Template(template_str)  # Creating template from user input
        result = template.substitute(message=user_message)  # SINK: Template injection
        logger.info(result)
    except (KeyError, ValueError):
        pass

    return {'logged': True}


def vulnerable_eval_in_logging(request):
    """
    VULNERABLE: Expression evaluation in log context

    The most dangerous Python equivalent: evaluating user expressions.
    This is the closest Python equivalent to Log4Shell's JNDI lookups.
    """
    expression = request.GET.get('expr', '')  # SOURCE: UserControlled

    # CRITICAL VULN: Evaluating user input (equivalent to Log4j expression evaluation)
    try:
        result = eval(expression)  # SINK: Remote Code Execution
        logger.info(f"Expression result: {result}")
    except Exception as e:
        logger.error(f"Expression error: {e}")

    return {'evaluated': True}


def vulnerable_jinja_logging(request):
    """
    VULNERABLE: Jinja2 template in logging context

    If log messages are later rendered through a template engine,
    SSTI can occur (chained vulnerability).
    """
    from jinja2 import Template

    user_data = request.POST.get('data', '')  # SOURCE: UserControlled

    # VULN: User input becomes part of template
    log_template = f"User submitted: {user_data}"

    # If this log is later rendered through Jinja2...
    template = Template(log_template)  # SINK: SSTI if user_data contains {{...}}
    rendered = template.render()

    logger.info(rendered)

    return {'rendered': True}


def vulnerable_dynamic_logger_config(request):
    """
    VULNERABLE: User-controlled logging configuration

    Similar to Log4j's ability to load remote configuration,
    allowing user control of logging config is dangerous.
    """
    # VULN: User controls log format/level
    log_format = request.POST.get('format', '%(message)s')  # SOURCE
    log_level = request.POST.get('level', 'INFO')  # SOURCE

    # Dangerous: User controls logging configuration
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(log_format))  # SINK: Config injection

    temp_logger = logging.getLogger('user_controlled')
    temp_logger.addHandler(handler)

    # Could be used for log injection attacks
    temp_logger.info("User controlled logging")

    return {'configured': True}


# ==============================================================================
# SECURE PATTERNS
# ==============================================================================

def secure_parameterized_logging(request):
    """
    SECURE: Using logging's built-in parameterization

    This is the recommended pattern - let the logging library handle formatting.
    User data is never interpreted as format string.
    """
    username = request.GET.get('username', '')

    # SECURE: Parameters passed separately, never interpreted as format
    logger.info("Login attempt for: %s", username)  # ✓ Safe
    logger.info("Login attempt for user", extra={'username': username})  # ✓ Safe

    return {'status': 'logged_safely'}


def secure_escaped_logging(request):
    """
    SECURE: Sanitize user input before any string operations
    """
    import html

    user_input = request.POST.get('message', '')

    # SECURE: Escape special characters
    sanitized = html.escape(user_input)
    sanitized = sanitized.replace('{', '{{').replace('}', '}}')  # Escape format chars
    sanitized = sanitized.replace('$', '\\$')  # Escape Template chars

    logger.info(f"User message (sanitized): {sanitized}")

    return {'logged': True}


def secure_structured_logging(request):
    """
    SECURE: Use structured logging (JSON) instead of string formatting

    Structured logging avoids format string issues entirely.
    """
    import json

    username = request.GET.get('username', '')
    action = request.GET.get('action', 'login')

    # SECURE: Structured data, no string formatting
    log_entry = {
        'event': 'user_action',
        'username': username,  # Data is data, not code
        'action': action,
        'timestamp': '2024-01-15T10:00:00Z'
    }

    logger.info(json.dumps(log_entry))  # ✓ Safe - JSON serialization

    return {'logged': True}


def secure_allowlist_format(request):
    """
    SECURE: If custom formats are needed, use strict allowlist
    """
    ALLOWED_FORMATS = {
        'simple': 'User: {username}',
        'detailed': 'User: {username}, Action: {action}',
        'timestamp': '[{timestamp}] User: {username}',
    }

    format_choice = request.GET.get('format', 'simple')
    username = request.GET.get('username', 'anonymous')

    # SECURE: Only predefined formats allowed
    if format_choice not in ALLOWED_FORMATS:
        format_choice = 'simple'

    template = ALLOWED_FORMATS[format_choice]
    message = template.format(
        username=username,
        action='login',
        timestamp='2024-01-15'
    )

    logger.info(message)

    return {'logged': True}

