"""FLEXT-LDIF - Centralized Type System.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Centralized type definitions following flext-core patterns.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path

# Basic type aliases
AttributeName = str
AttributeValue = str | bytes | int | float | bool
StringList = list[str]
FilePath = str | Path

# LDIF-specific types
LDIFContent = str
LDIFLines = list[str]
LDAPObjectClass = str

# Processing configuration types
ProcessingMode = str  # 'strict' | 'permissive' | 'fast'
ValidationLevel = str  # 'strict' | 'standard' | 'minimal'

# Dictionary types for data exchange
FlextLdifAttributesDict = dict[str, list[AttributeValue]]
FlextLdifDNDict = dict[str, str]
FlextLdifEntryDict = dict[str, str | int | float | bool | list[AttributeValue]]

# Type unions for flexibility
AttributeValueType = str | bytes | int | float | bool
MappingType = Mapping[str, str | int | float | bool]
SequenceType = Sequence[str | int | float | bool]

__all__ = [
    "AttributeName",
    "AttributeValue",
    "AttributeValueType",
    "FilePath",
    "FlextLdifAttributesDict",
    "FlextLdifDNDict",
    "FlextLdifEntryDict",
    "LDAPObjectClass",
    "LDIFContent",
    "LDIFLines",
    "MappingType",
    "ProcessingMode",
    "SequenceType",
    "StringList",
    "ValidationLevel",
]
