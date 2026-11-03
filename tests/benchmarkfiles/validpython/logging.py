# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import logging
import logging.config
import os
import tempfile


# sast_meta data
SAST_META = {
    "title": "Unsafe Logging Configuration Loading",
    "cwe_id": 502,              # Deserialization of Untrusted Data
                                # (also consider CWE-22 for log path traversal, CWE-117 for log injection)
    "weakness": "Deserialization of Untrusted Data",
    "owasp": "A08:2021 - Software and Data Integrity Failures",
    "severity": "Medium",
    "cvss": None,
    "impact": "Medium",
    "tags": ["logging", "logging-config", "dictConfig", "fileConfig", "deserialization", "log-injection"],
}


# ---------- Example 1: dictConfig (the recommended, safe-by-design API) ----------
def configure_logging_dict(log_file: str) -> None:
    """Configure logging from an in-code dict — no untrusted input involved."""
    logging.config.dictConfig({
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "std": {
                "format": "%(asctime)s %(levelname)s %(name)s: %(message)s",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "std",
                "level": "INFO",
            },
            "file": {
                "class": "logging.FileHandler",
                "filename": log_file,
                "formatter": "std",
                "level": "DEBUG",
                "encoding": "utf-8",
            },
        },
        "root": {
            "level": "DEBUG",
            "handlers": ["console", "file"],
        },
    })


# ---------- Example 2: fileConfig from a trusted path ----------
def configure_logging_file(config_path: str, base_dir: str) -> None:
    """
    Load an INI-style logging config with fileConfig.
    Confine the config path to a trusted base directory first.
    """
    resolved = os.path.realpath(config_path)
    if not resolved.startswith(os.path.realpath(base_dir) + os.sep):
        raise PermissionError(f"Config path escapes base directory: {config_path}")

    logging.config.fileConfig(
        resolved,
        disable_existing_loggers=False,
    )


# ---------- Example 3: dictConfig from JSON — only with a trusted source ----------
def configure_logging_json(json_path: str) -> None:
    """
    dictConfig can accept a dict parsed from JSON/YAML.
    ONLY do this if the file is under application control and integrity-checked.
    """
    import json
    with open(json_path, "r", encoding="utf-8") as f:
        config = json.load(f)
    logging.config.dictConfig(config)


# ---------- Unsafe pattern, shown for audit demonstration ----------
def unsafe_fileconfig_from_user_path(user_path: str) -> None:
    """VULNERABLE: fileConfig with a caller-controlled path."""
    logging.config.fileConfig(user_path)  # path traversal + arbitrary config injection


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        log_file = os.path.join(tmp, "app.log")
        configure_logging_dict(log_file)

        logger = logging.getLogger("demo")
        logger.info("Configured via logging.config.dictConfig")
        logger.debug("File handler active")

        print("--- app.log contents ---")
        with open(log_file, "r", encoding="utf-8") as f:
            print(f.read(), end="")