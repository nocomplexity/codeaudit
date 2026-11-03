# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0

# sast_meta data
SAST_META = {
    "title": "Use of Cryptographically Weak PRNG (random module) for Security-Sensitive Values",
    "cwe_id": [338, 330, 337],   # 338 Use of Cryptographically Weak PRNG, 330 Insufficiently Random Values, 337 Predictable Seed
    "weakness": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
    "owasp": "A04:2025 - Cryptographic Failures",
    "severity": "High",
    "cvss": 7.5,
    "impact": "High",
    "tags": ["random", "prng", "weak-randomness", "predictable-seed",
             "insecure-random", "cookie", "cryptographic-failure", "python"],
}

import random

"""Often Problematic code using random module"""
browser_cookie = random.randint(min_value, max_value)

def generate_random_float():
  """
  Generates a random floating-point number between 0.0 (inclusive) and 1.0 (exclusive).

  The random.random() function from Python's built-in 'random' module is used
  to produce this number.

  Returns:
    float: A random float between 0.0 and 1.0.
  """
  random.seed(23)
  random_number = random.random()
  return random_number


# Create a Random instance with a fixed seed for reproducibility
rng = random.Random(42)

# Generate a random number from 0 up to (but not including) 10
num1 = random.randrange(10)

num = random.randint(1, 10)

num_uni = random.uniform(1.0, 10.0)

num_tri = random.triangular(1.0, 10.0, 5.0)

# Generate a larger block of random bytes (e.g., 16 bytes)
more_data = random.randbytes(16)