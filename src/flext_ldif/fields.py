"""FLEXT-LDIF - Pydantic Field Definitions (Compatibility Facade).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

COMPATIBILITY FACADE: Field definitions are now consolidated in services.py
Import from services for backward compatibility.
"""

from __future__ import annotations

# Import field definitions from consolidated services module
from .services import (
    FieldDefaults,
    attribute_name_field,
    attribute_value_field,
    dn_field,
    object_class_field,
)

__all__ = [
    "FieldDefaults",
    "attribute_name_field",
    "attribute_value_field",
    "dn_field",
    "object_class_field",
]
