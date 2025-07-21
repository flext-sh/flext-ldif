"""LDIF type definitions using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import NewType

# LDIF-specific types
LDIFContent = NewType("LDIFContent", str)
LDIFLines = NewType("LDIFLines", list[str])
LDIFAttributes = NewType("LDIFAttributes", dict[str, list[str]])
DistinguishedName = NewType("DistinguishedName", str)

__all__ = [
    "DistinguishedName",
    "LDIFAttributes",
    "LDIFContent",
    "LDIFLines",
]
