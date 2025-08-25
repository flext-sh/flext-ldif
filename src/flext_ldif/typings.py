"""FLEXT-LDIF - Type System (Compatibility Facade).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

COMPATIBILITY FACADE: All types are now consolidated in utilities.py
Import everything from utilities for backward compatibility.
"""

from __future__ import annotations

# Import all type definitions from consolidated utilities module
from .utilities import (
    AttributeName,
    AttributeValue,
    AttributeValueType,
    FilePath,
    FlextLdifAttributesDict,
    FlextLdifDNDict,
    FlextLdifEntryDict,
    LDAPObjectClass,
    LDIFContent,
    LDIFLines,
    MappingType,
    ProcessingMode,
    SequenceType,
    StringList,
    ValidationLevel,
)

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
