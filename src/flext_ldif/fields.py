"""FLEXT-LDIF - Pydantic Field Definitions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Centralized field definitions following pydantic patterns.
"""

from __future__ import annotations

from typing import ClassVar, cast

from pydantic import Field
from pydantic.fields import FieldInfo


# DN field with validation
def dn_field(
    *,
    description: str = "Distinguished Name",
    min_length: int = 1,
    max_length: int = 1024,
) -> FieldInfo:
    """Create a DN field with standard validation."""
    return cast(
        "FieldInfo",
        Field(
            description=description,
            min_length=min_length,
            max_length=max_length,
        ),
    )


# Attribute name field
def attribute_name_field(
    *,
    description: str = "LDAP Attribute Name",
    pattern: str = r"^[a-zA-Z][a-zA-Z0-9\-]*$",
    max_length: int = 255,
) -> FieldInfo:
    """Create an attribute name field with validation."""
    return cast(
        "FieldInfo",
        Field(
            description=description,
            pattern=pattern,
            max_length=max_length,
        ),
    )


# Attribute value field
def attribute_value_field(
    *,
    description: str = "LDAP Attribute Value",
    max_length: int = 65536,
) -> FieldInfo:
    """Create an attribute value field with validation."""
    return cast(
        "FieldInfo",
        Field(
            description=description,
            max_length=max_length,
        ),
    )


# Object class field
def object_class_field(
    *,
    description: str = "LDAP Object Class",
    pattern: str = r"^[a-zA-Z][a-zA-Z0-9\-]*$",
    max_length: int = 255,
) -> FieldInfo:
    """Create an object class field with validation."""
    return cast(
        "FieldInfo",
        Field(
            description=description,
            pattern=pattern,
            max_length=max_length,
        ),
    )


# Common field constants
class FieldDefaults:
    """Default values for common field configurations."""

    DN_MAX_LENGTH: ClassVar[int] = 1024
    ATTRIBUTE_NAME_MAX_LENGTH: ClassVar[int] = 255
    ATTRIBUTE_VALUE_MAX_LENGTH: ClassVar[int] = 65536
    LDIF_LINE_MAX_LENGTH: ClassVar[int] = 76

    DN_PATTERN: ClassVar[str] = r"^[a-zA-Z][a-zA-Z0-9\-=,\s]*$"
    ATTRIBUTE_NAME_PATTERN: ClassVar[str] = r"^[a-zA-Z][a-zA-Z0-9\-]*$"


__all__ = [
    "FieldDefaults",
    "attribute_name_field",
    "attribute_value_field",
    "dn_field",
    "object_class_field",
]
