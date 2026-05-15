# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later

import base64

payload = b"import os; os.system('malicious command')"

# Encoding (attacker side)
encoded_b64 = base64.b64encode(payload)

# Decoding patterns (common in malware)
decoded1 = base64.b64decode(encoded_b64)  # Most common
decoded2 = base64.z85decode(base64.b85encode(payload))  # Less common

b64 = base64.b64decode
exec(b64(payload))  # alias use should be detected!


print("b64 encoded :", encoded_b64)
print("b64 decoded :", decoded1)
