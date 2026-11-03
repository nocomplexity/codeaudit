# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 

import os
import sys
import json

# SAST Metadata
SAST_META = {
    "title": "Overly Broad Exception Handling",
    "cwe_id": [703, 390, 755],  # 703 improper check or handling of exceptional conditions,
                                # 390 detection of error condition without action,
                                # 755 improper handling of exceptional conditions
    "weakness": "Improper Check or Handling of Exceptional Conditions",
    "owasp": "A09:2021 - Security Logging and Monitoring Failures",
    "severity": "Medium",
    "cvss": None,
    "impact": "Medium",
    "tags": ["exception-handling", "error-suppression", "bare-except",
             "silent-failure", "logging", "fail-open"],
}


def load_config(paths):
    """Process multiple config files, skipping bad ones."""
    results = []
    for path in paths:
        try:
            with open(path) as f:
                results.append(json.load(f))
        except Exception:      # <-- overly broad
            pass               # <-- silent swallow: no log, no alert, fail-open
    return results


def process_records(records):
    """Validate records, silently dropping anything that fails."""
    valid = []
    for rec in records:
        try:
            # In a real app: schema validation, permission check, etc.
            assert isinstance(rec, dict) and "id" in rec
            valid.append(rec)
        except Exception:      # <-- catches everything incl. AssertionError, MemoryError
            continue           # <-- loop keeps going with no visibility
    return valid


def demonstrate_broad_except():
    """
    Demonstrates the anti-pattern:
      - 'except Exception: pass'   -> errors vanish, caller can't tell
      - 'except Exception: continue' -> bad input silently dropped

    Both violate the principle of failing closed / failing loudly.
    """
    print("[*] Broad-except demo (intentionally vulnerable pattern)")

    # 1) pass: missing/corrupt files are silently ignored
    configs = load_config(["missing.json", "/etc/shadow", "corrupt.json"])
    print(f"    loaded {len(configs)} config(s) — caller has NO idea why others failed")

    # 2) continue: attacker-supplied malformed records are silently dropped
    records = [{"id": 1}, {"id": 2}, "not-a-dict", None, {"noid": True}]
    kept = process_records(records)
    print(f"    kept {len(kept)}/{len(records)} records — rejections are invisible")

    # In a real system: a permission error on /etc/shadow (should be fatal
    # or at least logged) is indistinguishable from a benign missing file.
    # An attacker can suppress security-relevant errors by crafting input
    # that triggers exceptions in the silent branch.


# ---- Recommended alternative (for contrast) ----
def load_config_safe(paths):
    results = []
    for path in paths:
        try:
            with open(path) as f:
                results.append(json.load(f))
        except FileNotFoundError as e:
            print(f"[warn] missing config {path}: {e}", file=sys.stderr)
        except PermissionError as e:
            # security-relevant: fail closed
            raise RuntimeError(f"refusing to continue, cannot read {path}") from e
        except json.JSONDecodeError as e:
            print(f"[warn] corrupt config {path}: {e}", file=sys.stderr)
    return results


if __name__ == "__main__":
    demonstrate_broad_except()
    print()
    print("[*] Safe variant (for comparison):")
    try:
        load_config_safe(["missing.json"])
    except Exception as e:
        print(f"    raised as expected: {type(e).__name__}: {e}")