"""LDIF type definitions using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import NewType

# Simple type aliases that don't conflict with domain value objects
LDIFContent = NewType("LDIFContent", str)
LDIFLines = NewType("LDIFLines", list[str])

# Note: DistinguishedName and LDIFAttributes are proper domain value objects
# defined in domain/values.py, not simple type aliases

__all__ = [
    "LDIFContent",
    "LDIFLines",
]
