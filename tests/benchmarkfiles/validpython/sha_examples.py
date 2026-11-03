# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 


# sast_meta data
SAST_META = {
    "title": "Use of Weak Cryptographic Hash Algorithms (MD5 / SHA1)",
    "cwe_id": [327, 328],   # 327 Use of a Broken or Risky Cryptographic Algorithm, 328 Use of Weak Hash
    "weakness": "Use of a Broken or Risky Cryptographic Algorithm",
    "owasp": "A04:2025 - Cryptographic Failures",
    "severity": "High",
    "cvss": 7.5,
    "impact": "High",
    "tags": ["md5", "sha1", "weak-hash", "hashlib", "cryptographic-failure",
             "broken-algorithm", "python"],
}

import hashlib

# This will raise a ValueError in Python 3.9+ unless usedforsecurity=False
md5_hash = hashlib.md5(b"data")  # ValueError in FIPS mode

# Explicit opt-out - indicates non-security use
md5_hash = hashlib.md5(b"data", usedforsecurity=False)
sha_hash = hashlib.sha1(b"data")