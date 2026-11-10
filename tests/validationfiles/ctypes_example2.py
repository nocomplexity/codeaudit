# SPDX-FileCopyrightText: 2026-present Maikel Mardjan(https://nocomplexity.com/) and all contributors!
# SPDX-License-Identifier: GPL-3.0-or-later
# See for full license text: https://spdx.org/licenses/GPL-3.0-or-later.html or https://opensource.org/license/gpl-3.0 
import ctypes as ct
lib1 = ct.CDLL("mylib.so")

from ctypes import CDLL as safeloader
lib2 = safeloader("mylib.so")

from ctypes import CDLL as noevil

safe_variable = noevil("mymalwarelib.so")